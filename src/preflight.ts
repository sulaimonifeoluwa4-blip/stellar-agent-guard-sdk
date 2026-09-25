/**
 * The pre-flight interceptor: ask the guard whether an action is permitted
 * *before* anything is signed for broadcast.
 *
 * This is the surface an agent framework integrates with. It answers one
 * question — "may this call proceed?" — and it answers it the same way the chain
 * would, because it runs the same enforcement: the guarded account's real
 * `__check_auth` against live ledger state, in a simulation that cannot mutate
 * anything. A refusal therefore costs nothing and cannot be bypassed by an agent
 * that ignores the answer, since the on-chain check still stands behind it.
 *
 * Three distinct answers, kept distinct on purpose:
 *
 *  - `admissible` — the guard approved. `estimatedResourceFee` is the network's
 *    own price for the call, taken from the same simulation.
 *  - `blocked` — the guard refused, with the contract's own reason. This is the
 *    guardrail working, and the reason is safe to show an operator.
 *  - `undetermined` — the enforcement run failed for a reason that is not a
 *    policy decision (a contract trap, a missing trustline, an unsupported
 *    credential type). **Treated as not-allowed**, because a guardrail must fail
 *    closed, but reported separately so an adapter never claims the guard
 *    refused something it never ruled on.
 *
 * A refused call never has a transaction hash. That is not a gap in the
 * evidence: the block happens before broadcast, which is what makes it free.
 */
import { createHash } from "node:crypto";
import { Keypair, rpc } from "@stellar/stellar-sdk";
import { enforceCall } from "./invoke.ts";
import { GuardBlockedError, explainReason } from "./reasons.ts";
import type { ContractCall } from "./tx.ts";

/**
 * Thrown when enforcement could not reach a decision.
 *
 * Deliberately not a `GuardBlockedError`: reporting "the guard refused this"
 * when the guard never ruled would be a false claim about the security
 * boundary, which is the one thing an operator must be able to trust.
 */
export class PreFlightUndeterminedError extends Error {
  readonly detail: string;

  constructor(detail: string) {
    super(`stellar-agent-guard could not determine this action's status\n${detail}`);
    this.name = "PreFlightUndeterminedError";
    this.detail = detail;
  }
}

export type PreFlightDecision =
  | {
      allowed: true;
      kind: "admissible";
      /** The network's own resource fee estimate for this call, in stroops. */
      estimatedResourceFee: bigint;
      /** Number of ledger keys the call is priced to touch. */
      footprintKeys: number;
    }
  | {
      allowed: false;
      kind: "blocked";
      /** The contract's reason symbol, e.g. `per_tx_cap_exceeded`. */
      reason: string;
      /** One-line operator-facing meaning of `reason`. */
      explanation: string;
      detail: string;
      diagnosticEvents: unknown[];
    }
  | {
      allowed: false;
      kind: "undetermined";
      detail: string;
    };

export type PolicyRevision = string | number | bigint | boolean | null | undefined;

export interface PreFlightCacheOptions {
  /** Maximum age of a cached verdict; capped at one ledger close window. */
  ttlMs?: number;
  /** Ledger-based spelling of `ttlMs`; one ledger is approximately five seconds. */
  ttlLedgers?: number;
  /**
   * Optional policy revision, or a getter for it. Supplying this makes policy
   * changes invalidate the cache before the next ledger boundary.
   */
  policyRevision?: PolicyRevision | (() => PolicyRevision | Promise<PolicyRevision>);
}

export interface PreFlightConfig {
  server: rpc.Server;
  networkPassphrase: string;
  /** The guarded smart account whose policy is being enforced. */
  guard: string;
  /** The key registered as the account's agent, used to sign the auth entry. */
  agent: Keypair;
  /** Classic account that pays fees and supplies the sequence number. */
  source: Keypair;
  /** Authorizers for non-guard requirements (e.g. an admin on a policy call). */
  accountSigners?: Keypair[];
  /** Opt-in short-lived simulation-result cache. Caching is disabled by default. */
  cache?: PreFlightCacheOptions;
}

export type PreFlightInterceptorOptions = PreFlightConfig;

const LEDGER_CLOSE_MS = 5_000;
const MAX_CACHE_TTL_MS = LEDGER_CLOSE_MS;

interface CacheEntry {
  decision: PreFlightDecision;
  ledger: number;
  expiresAt: number;
}

interface CacheContext {
  key: string;
  ledger: number;
  expiresAt: number;
}

function policyRevisionToken(revision: PolicyRevision): string {
  if (revision === undefined) return "unknown";
  if (revision === null) return "null";
  return `${typeof revision}:${String(revision)}`;
}

function callFingerprint(call: ContractCall): string {
  const args = createHash("sha256");
  for (const arg of call.args) {
    args.update(Buffer.from(arg.toXDR()));
    args.update(Buffer.from([0]));
  }
  return createHash("sha256")
    .update(call.contract)
    .update(Buffer.from([0]))
    .update(call.fn)
    .update(Buffer.from([0]))
    .update(args.digest())
    .digest("hex");
}

export class PreFlightInterceptor {
  private readonly config: PreFlightConfig;
  private readonly cacheOptions: PreFlightCacheOptions | undefined;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(config: PreFlightConfig) {
    this.config = config;
    this.cacheOptions = config.cache;
    this.validateCacheOptions();
  }

  private validateCacheOptions(): void {
    if (!this.cacheOptions) return;
    const { ttlMs, ttlLedgers } = this.cacheOptions;
    if (ttlMs === undefined && ttlLedgers === undefined) {
      throw new TypeError("preflight cache requires ttlMs or ttlLedgers");
    }
    if (ttlMs !== undefined && (!Number.isFinite(ttlMs) || ttlMs <= 0)) {
      throw new TypeError("preflight cache ttlMs must be a positive finite number");
    }
    if (ttlLedgers !== undefined && (!Number.isFinite(ttlLedgers) || ttlLedgers <= 0)) {
      throw new TypeError("preflight cache ttlLedgers must be a positive finite number");
    }
  }

  private cacheTtlMs(): number {
    const { ttlMs, ttlLedgers } = this.cacheOptions ?? {};
    const requested = ttlMs ?? (ttlLedgers ?? 0) * LEDGER_CLOSE_MS;
    return Math.min(requested, MAX_CACHE_TTL_MS);
  }

  private async cacheContext(call: ContractCall): Promise<CacheContext | null> {
    if (!this.cacheOptions) return null;

    let revision: PolicyRevision;
    try {
      revision =
        typeof this.cacheOptions.policyRevision === "function"
          ? await this.cacheOptions.policyRevision()
          : this.cacheOptions.policyRevision;
    } catch {
      // A revision read failure must not turn a cache miss into a failed
      // security decision. The uncached path below will report the real result.
      return null;
    }

    let ledger: number;
    try {
      const latest = await this.config.server.getLatestLedger();
      ledger = latest.sequence;
    } catch {
      return null;
    }

    return {
      key: `${callFingerprint(call)}:${policyRevisionToken(revision)}`,
      ledger,
      expiresAt: Date.now() + this.cacheTtlMs(),
    };
  }

  /** Clear all cached verdicts, or only entries for `call` when provided. */
  invalidate(call?: ContractCall): void {
    if (!call) {
      this.cache.clear();
      return;
    }
    const prefix = `${callFingerprint(call)}:`;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) this.cache.delete(key);
    }
  }

  /**
   * Decide whether `call` may proceed. Never broadcasts, never mutates, never
   * throws for a refusal — a block is a normal, expected result.
   */
  async check(call: ContractCall): Promise<PreFlightDecision> {
    const context = await this.cacheContext(call);
    if (context) {
      const cached = this.cache.get(context.key);
      if (cached && cached.ledger === context.ledger && cached.expiresAt > Date.now()) {
        return cached.decision;
      }
    }

    const outcome = await enforceCall({
      server: this.config.server,
      source: this.config.source,
      call,
      networkPassphrase: this.config.networkPassphrase,
      guardAuth: { guard: this.config.guard, agent: this.config.agent },
      ...(this.config.accountSigners ? { accountSigners: this.config.accountSigners } : {}),
    });

    let decision: PreFlightDecision;
    if (outcome.kind === "error") {
      decision = { allowed: false, kind: "undetermined", detail: outcome.detail };
    } else if (outcome.kind === "blocked") {
      decision = {
        allowed: false,
        kind: "blocked",
        reason: outcome.reason,
        explanation: explainReason(outcome.reason),
        detail: outcome.detail,
        diagnosticEvents: outcome.diagnosticEvents,
      };
    } else {
      const data = outcome.simulation.transactionData as unknown as
        | { getReadOnly?: () => unknown[]; getReadWrite?: () => unknown[] }
        | undefined;
      const footprintKeys =
        (data?.getReadOnly?.().length ?? 0) + (data?.getReadWrite?.().length ?? 0);
      decision = {
        allowed: true,
        kind: "admissible",
        estimatedResourceFee: BigInt(outcome.simulation.minResourceFee ?? 0),
        footprintKeys,
      };
    }

    // An undetermined result is not a verdict and may be transient, so it is
    // deliberately not cached. Actual admissible/blocked results are.
    if (context && decision.kind !== "undetermined") {
      this.cache.set(context.key, { decision, ledger: context.ledger, expiresAt: context.expiresAt });
    }
    return decision;
  }

  /**
   * Convenience for adapters that want a throw-on-refusal shape.
   *
   * Throws `GuardBlockedError` for both `blocked` and `undetermined` — an
   * interceptor that returned happily on `undetermined` would hand an agent a
   * green light the chain never gave.
   */
  async assertAllowed(call: ContractCall): Promise<PreFlightDecision & { allowed: true }> {
    const decision = await this.check(call);
    if (decision.allowed) return decision;
    if (decision.kind === "blocked") {
      throw new GuardBlockedError({
        reason: decision.reason,
        stage: "preflight",
        detail: decision.detail,
      });
    }
    throw new PreFlightUndeterminedError(decision.detail);
  }
}

/** One-shot form, for callers that do not want to hold an interceptor. */
export function preflight(config: PreFlightConfig, call: ContractCall): Promise<PreFlightDecision> {
  return new PreFlightInterceptor(config).check(call);
}
