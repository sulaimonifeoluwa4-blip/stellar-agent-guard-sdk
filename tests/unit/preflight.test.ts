import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Account, Keypair, nativeToScVal, rpc } from "@stellar/stellar-sdk";
import { PreFlightInterceptor, type PreFlightCacheOptions } from "../../src/preflight.ts";
import type { ContractCall } from "../../src/tx.ts";

const contract = "CAPADGEK457RHKN4RYVUMDJTFHDSG7R5HREQONKLYK7MFKC5WFENPP44";
const call: ContractCall = { contract, fn: "noop", args: [] };

function makeServer() {
  let simulations = 0;
  let ledger = 100;
  const source = Keypair.random();
  const server = {
    getAccount: async () => new Account(source.publicKey(), "1"),
    getLatestLedger: async () => ({ sequence: ledger }),
    simulateTransaction: async () => {
      simulations += 1;
      return {
        result: { auth: [] },
        minResourceFee: "17",
        transactionData: {
          getReadOnly: () => [],
          getReadWrite: () => [{}],
        },
      };
    },
  } as unknown as rpc.Server;

  return {
    server,
    source,
    call,
    get simulations() {
      return simulations;
    },
    advanceLedger() {
      ledger += 1;
    },
  };
}

function interceptor(
  server: rpc.Server,
  source: Keypair,
  options: { cache?: PreFlightCacheOptions } = {},
) {
  return new PreFlightInterceptor({
    server,
    networkPassphrase: "Test SDF Network ; September 2015",
    guard: contract,
    agent: source,
    source,
    ...options,
  });
}

describe("PreFlightInterceptor simulation cache", () => {
  it("does not cache unless explicitly enabled", async () => {
    const harness = makeServer();
    const guarded = interceptor(harness.server, harness.source, {});

    await guarded.check(harness.call);
    await guarded.check(harness.call);

    assert.equal(harness.simulations, 4);
  });

  it("returns a hit for the same call within the ledger window", async () => {
    const harness = makeServer();
    const guarded = interceptor(harness.server, harness.source, { cache: { ttlMs: 5_000 } });

    const first = await guarded.check(harness.call);
    const second = await guarded.check(harness.call);

    assert.equal(harness.simulations, 2);
    assert.equal(second, first);
  });

  it("does not reuse a verdict after its TTL expires", async () => {
    const harness = makeServer();
    const guarded = interceptor(harness.server, harness.source, { cache: { ttlMs: 1 } });

    await guarded.check(harness.call);
    await new Promise((resolve) => setTimeout(resolve, 5));
    await guarded.check(harness.call);

    assert.equal(harness.simulations, 4);
  });

  it("supports explicit invalidation", async () => {
    const harness = makeServer();
    const guarded = interceptor(harness.server, harness.source, { cache: { ttlMs: 5_000 } });

    await guarded.check(harness.call);
    guarded.invalidate();
    await guarded.check(harness.call);

    assert.equal(harness.simulations, 4);
  });

  it("invalidates when the ledger advances", async () => {
    const harness = makeServer();
    const guarded = interceptor(harness.server, harness.source, { cache: { ttlMs: 5_000 } });

    await guarded.check(harness.call);
    harness.advanceLedger();
    await guarded.check(harness.call);

    assert.equal(harness.simulations, 4);
  });

  it("invalidates when the policy revision changes", async () => {
    const harness = makeServer();
    let revision = 1;
    const guarded = interceptor(harness.server, harness.source, {
      cache: { ttlMs: 5_000, policyRevision: () => revision },
    });

    await guarded.check(harness.call);
    revision = 2;
    await guarded.check(harness.call);

    assert.equal(harness.simulations, 4);
  });

  it("uses different keys for different arguments", async () => {
    const harness = makeServer();
    const guarded = interceptor(harness.server, harness.source, { cache: { ttlMs: 5_000 } });
    const otherCall: ContractCall = {
      contract,
      fn: "noop",
      args: [nativeToScVal(1n, { type: "i128" })],
    };

    await guarded.check(harness.call);
    await guarded.check(otherCall);

    assert.equal(harness.simulations, 4);
  });
});
