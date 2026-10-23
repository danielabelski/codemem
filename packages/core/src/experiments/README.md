# Isolated semantic ranking prototype

This experiment is not enabled by the CLI, viewer, MCP server, configuration, or
environment. The normal inline semantic path remains the default. The experiment
has no package export and requires explicit fixture injection.

## Fixture injection

Initialize an owned file-backed fixture with the normal parent store. Inject its
runtime signing public key through the existing `MemoryStore` constructor option;
isolate HOME, XDG directories, all `CODEMEM_*` settings, and networking. Never use
an actual profile or download a model for these fixtures.

This generation-backed mode requires the explicit **all writers upgraded, writer
version 1** contract. The fixture owner initializes the validated index, seeds
vectors through `writeValidatedBatch`, starts an audit with its known models, and
finishes the audit before dispatching semantic requests. The worker never creates
this metadata or starts an audit. Absent, building, repair-needed, or empty indexes
use the existing non-semantic pack path without loading a client, starting a worker,
or reading an actual signing key. Existing browsing fallbacks may still add items.

All later vector writes/deletions must use the validated writer APIs. Raw vector
SQL and older writers are unsupported: invalidate the index before those writes
and audit/rebuild before reuse. Direct memory-content changes remain subject to
the parent's current content checks. This is a fixture contract, not a production
writer upgrade or automatic schema migration.

```ts
const executor = createExperimentalSemanticExecutor({
  store,
  getClient: async () => offlineFixtureClient,
});
attachExperimentalSemanticExecutor(store, executor);
// Pass this store to the actual viewer createApp or MCP server fixture.
// Exercise their existing pack routes/tools, not a replacement pack implementation.
await executor.close();
store.close();
```

Import the factory from `semantic-worker-executor.ts` and the attachment function
from `semantic-executor-seam.ts`. All three asynchronous pack builders use the
injected executor; assembly, usage, traces, and retrieval-ledger ownership stay in
the parent. Worker failure uses the existing non-semantic fallback, never inline
ranking SQL fallback.
An observed identity/key/file change rejects the build rather than delivering a
keyword-only response under a different identity.

## Boundary and limits

- One active semantic operation, including embedding; four pending by default.
- Request deadline: 15 seconds from enqueue. Readiness deadline: 5 seconds.
  Typed queue options let deterministic lifecycle tests shorten these values.
- Queued abort/expiry removes the request immediately. Active abort/expiry stops
  waiting but retains the slot until preparation/native work completes or exit is
  confirmed. A synchronous SQLite call cannot process a cancellation message.
- Crashes open a permanent circuit for this executor. No restart or replay.
- Shutdown stops admission, rejects pending requests, and drains for 5 seconds
  before requesting termination. It awaits confirmed worker exit and any parent
  embedding preparation. Neither native termination nor embedding completion has
  a hard time guarantee; `close()` can exceed the drain budget.
- `:memory:` is rejected. Existing inline in-memory tests provide no event-loop
  isolation guarantee. Uncommitted parent transactions are rejected as well.

The worker uses the existing read-only connection loader, loads sqlite-vec, and
sets `query_only`. Its environment does not inherit parent profile settings or
credentials. It never constructs a store, reads a private key, or accepts SQL
or executable code. It recomputes same-actor peers, effective visible scopes,
automatic continuity, and compatible models inside its own read snapshot.

The parent captures public proof through its existing actual-key loader and checks
it again at completion, with at most two key loads per search. Queue and embedding
checkpoints recheck actor/device identity without loading the key. Empty vector
catalogs skip client loading, and incompatible models skip embedding. The parent
and worker use the same pure compatible-model resolver over cheap catalog labels
and current migration metadata; request paths do not scan the vec0 model catalog.

The worker returns the validated generation, selected models, per-candidate vector
versions, and content identities. The parent compares the generation/model
decision and candidate versions, including tombstones and missing model pairs,
then reloads current authorized payloads and automatic continuity in a short read
snapshot. Usage/ledger writes and unrelated vector writes do not discard valid
results. Catalog revision is diagnostic only; a newly added unrelated memory does
not require reranking an already valid snapshot. Candidate content/vector changes,
an invalid generation, or a changed compatible-model decision discard semantic
results. There is no whole-database write stamp or vector-BLOB fingerprint pass.
This is not atomic cross-process revocation: a commit after the last read snapshot
can still race delivery.

## Source and emitted workers

Source workers use Node 24's TypeScript transform flag because the existing DB
loader graph contains parameter properties. A thread-local resolution hook maps
the repository's relative `.js` imports to `.ts`; it does not evaluate generated
code or affect the parent. Emitted workers use ordinary JS without that flag.

Build the separate artifact with:

```sh
pnpm --filter @codemem/core exec vite build --config vite.experiments.config.ts
```

Artifacts land under the ignored core `dist/experiments/` directory. The ordinary
core build does not enable or build this experiment and can replace that directory.
Pack attachment currently requires the `source` export condition: the compiled
core pack has a separate attachment table with no exported setter. An emitted
executor smoke test does not prove installed or relocated pack integration.

Functional tests exercise viewer `app.request` and the real MCP server over in-memory transport.
Real HTTP responsiveness, overload behavior, native termination latency, and
remaining parent embedding/pack costs need separate performance evidence.
