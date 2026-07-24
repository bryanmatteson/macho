# Plan 0002 — Greenfield Splice instrumentation

**State:** reviewed agent-executable implementation contract. The slices in this document are
dependency order, not calendar phases. Format, schema, capability, safety, and
verifier implications absorb now; only explicitly marked native runtimes may be
gated.

## 1. Product decision and authority

Splice becomes one product with three coherent facets: transformation,
instrumentation, and analysis. There is one user-facing executable and command
surface, `splice`. Instrumentation may use multiple private provider and agent
binaries or an explicitly registered in-process extension, but those components
are not independent products and expose no public CLI.

Refrida is retired as a product, implementation dependency, compatibility
target, schema authority, and migration source. Its repository may be consulted
only as non-normative research and as a source of adversarial scenarios. No
production, conformance, packaging, help, or generated-authority path in Splice
depends on a Refrida crate, artifact, schema identity, CLI alias, extension ABI,
verifier clause, analysis edge, or byte-for-byte parity fixture.

Existing Splice v1 remains valid. In particular:

- `splice.report/v1`, current file/process Plans, current toolkit operations,
  and current CLI commands remain byte- and behavior-compatible;
- generic `ProcessEdit` remains width preserving and cannot allocate, launch,
  load, call target code, or install a hook;
- instrumentation is additive and uses a new schema namespace; and
- the workspace package version becomes `1.1.0`, not a breaking major release.

The new public schema identities are:

```text
splice.instrumentation.profile/v1
splice.instrumentation.request/v1
splice.instrumentation.provider/v1
splice.instrumentation.providers/v1
splice.instrumentation.agent/v1
splice.instrumentation.session/v1
splice.instrumentation.manifest/v1
splice.instrumentation.report/v1
splice.instrumentation.analysis/v1
splice.instrumentation.analysis-manifest/v1
```

`splice.report/v1` never accepts an instrumentation report. The single CLI
emits the schema belonging to the selected command family.

Canonical absorption updates `spec/splice-design.md`,
`spec/splice-language-spec.md`, and `spec/splice-as-agent.md`, and adds
`spec/splice-instrumentation.md`. The instrumentation specification controls
instrumentation behavior. `splice-as-agent.md` continues to govern the existing
fixed-width embedded actuator profile and gains an explicit pointer to the new
resident instrumentation profile; its current blanket refusals of injection,
hooks, events, and long-lived coordination are narrowed to the old profile.

No instrumentation source-language syntax ships in v1. The public surfaces are
the toolkit, generated schemas, and `splice instrument ...` CLI. Adding language
syntax later requires a new explicit specification change but not an artifact
schema redesign.

## 2. Included scope and runtime gates

| ID | Surface | Contract disposition | Runtime disposition |
|---|---|---|---|
| I001 | provider protocol and in-process extension equivalence | ABSORBED | implemented virtually and on Darwin ARM64 |
| I002 | launch, attach, target admission, and process identity | ABSORBED | Darwin ARM64 implemented |
| I003 | exact data/executable allocation and release | ABSORBED | virtual plus Darwin ARM64 implemented |
| I004 | launch-time and attach-time library delivery | ABSORBED | virtual plus Darwin ARM64 implemented |
| I005 | ARM64 and x86-64 entry-hook relocation | ABSORBED | pure implementation for both architectures |
| I006 | reviewed hook install/remove and durable action records | ABSORBED | virtual plus Darwin ARM64 implemented |
| I007 | resident agent ABI and bounded control protocol | ABSORBED | Darwin ARM64 implemented |
| I008 | capture profile, inventory, events, payloads, and loss | ABSORBED | virtual plus Darwin ARM64 implemented |
| I009 | crash-safe session ledger, CAS, manifest, and seal | ABSORBED | implemented portably |
| I010 | independent raw-session verifier | ABSORBED | implemented portably |
| I011 | deterministic decode, analysis, report, redaction, and diff | ABSORBED | implemented portably |
| I012 | Darwin SIP, hardened-runtime, signing, and library-validation profile | ABSORBED | Darwin ARM64 implemented |
| I013 | Darwin x86-64 native provider | ABSORBED | `gated:provider-darwin-x86_64` |
| I014 | Linux ARM64/x86-64 native providers | ABSORBED | `gated:provider-linux` |
| I015 | Windows x86-64 native provider | ABSORBED | `gated:provider-windows` |
| I016 | arbitrary public remote call or arbitrary RPC | EXCLUDED | schema and surface reject it |
| I017 | third-party extractor, decoder, or ruleset execution | EXCLUDED in v1 | built-in profile only |
| I018 | Refrida compatibility and migration | EXCLUDED | dependency and authority scans enforce it |

Gated native profiles still declare complete capability vocabulary, report
arms, diagnostics, verifier opinions, packaging identities, and applicable
conformance cases. A generated gated provider profile has
`runtime_state = gated`, no executable path or digest, and every runtime
capability false. An installed product manifest may carry that explicit gated
entry. No capability is inferred from Darwin ARM64 success.

## 3. Product and package architecture

### 3.1 One CLI, multiple private executables

```text
splice                              public CLI
├── splice-provider-darwin          private native provider
├── splice-provider-linux           private gated provider
├── splice-provider-windows         private gated provider
├── splice-instrument-supervisor    private detached-session supervisor
└── splice-agent-<os>-<arch>         private injected resident payload
```

Only `splice` is documented or accepted as a user command. A provider binary
started without the inherited provider channel and one-time token rejects and
exits. Provider binaries do not parse public CLI commands, listen on ambient
sockets, discover plugins, or read user profiles directly.
The supervisor likewise rejects direct launch without its inherited control
channel, authenticated store lease, and one-time token.

The installed product carries a canonical
`splice.instrumentation.providers/v1` manifest adjacent to `splice`. An
active entry names one private executable by product-relative path, platform,
architecture, provider id/version, provider-protocol version, and SHA-256. A
gated entry has no path or digest, declares `runtime_state = gated`, and
advertises every capability false. Discovery never searches `PATH`, the
working directory, environment variables, or arbitrary library directories. An
embedding host may instead register one trusted in-process
`InstrumentationProvider`; explicit registration is the only extension path.
The same manifest carries exactly one private supervisor component entry with
product-relative path, protocol version, and SHA-256.

### 3.2 Workspace ownership

- `splice-engine` owns provider-neutral value types, typed schemas, component
  traits, limits, diagnostics, opaque live handles, and canonical identities.
- `splice` owns `InstrumentationEngine`, pure planning, review,
  orchestration, action/session stores, report construction, semantic
  validation, raw verification, analysis, rendering, and diff.
- `carve` owns pure architecture decode/relocation. It receives bytes
  and addresses and has no process, provider, store, or transport access.
- `apps/splice-cli` owns the single public command tree and private-component
  spawning.
- private `apps/splice-provider-*` packages own platform access and optional
  Frida integration.
- private `apps/splice-instrument-supervisor` owns detached provider/session
  leases and the authenticated local reconnection broker.
- private `crates/splice-agent-*` packages produce injected agent artifacts and
  export only the closed resident ABI.
- `splice-conformance` and `xtask` own virtual providers, protocol runners,
  invalid corpora, native profiles, packaging checks, and retirement scans.

`InstrumentationEngine` is distinct from the current `Engine` operation slot.
An instrumentation session owns a serialized control queue while capture data
arrives concurrently through its bounded data channel. Existing `Engine`
re-entry behavior is unchanged.

### 3.3 Native and unsafe boundary

Published libraries and portable applications retain `unsafe_code = "forbid"`.
Only private native provider and agent packages may opt out of the workspace
lint. Each such package must:

- deny `unsafe_op_in_unsafe_fn` and undocumented unsafe blocks;
- confine unsafe Rust to `native` modules named in `xtask boundary-check`;
- expose safe typed provider/agent operations to the rest of the workspace;
- have one test or native conformance case for every unsafe entry point;
- ship no library target consumed by a published crate; and
- record third-party native licenses and artifact digests in the release bundle.

Frida is one optional Darwin provider implementation detail. It is neither a
public Splice API nor a core dependency. Its version, license inventory, linked
artifacts, and digest appear in the provider manifest and release SBOM.

## 4. Common identity, review, and durable stores

### 4.1 Identities

```text
InstrumentationProviderRef {
  id,
  version,
  protocol,
  placement: private_process | in_process_extension,
  executable_sha256?,
  host_registration_sha256?
}
ProcessGeneration = non-reused provider-domain string
ModuleGeneration  = non-reused provider-domain string
SessionId         = "splice-session-v1:" + 64 lowercase hex
ActionId          = "splice-action-v1:" + 64 lowercase hex
AllocationId      = "splice-allocation-v1:" + 64 lowercase hex
LibraryId         = "splice-library-v1:" + 64 lowercase hex
HookId            = "splice-hook-v1:" + 64 lowercase hex
```

Session IDs derive from canonical start intent plus 256 bits of randomness. The
first durable idempotency reservation assigns a monotonic action ordinal and
derives the Action ID from session ID, that ordinal, canonical request digest,
and idempotency key. An equal retry resolves the existing reservation and
consumes no new ordinal; reuse with different canonical request bytes rejects
`idempotency_conflict`. Allocation, library, and hook IDs derive from the
terminal successful action receipt.

PID, path, executable digest, and module bytes are never process or module
generation identities.

A `private_process` provider ref requires `executable_sha256` and forbids
`host_registration_sha256`. An `in_process_extension` ref requires
`host_registration_sha256` over the canonical immutable registration
identity and capabilities and forbids `executable_sha256`. Missing, extra, or
cross-arm identity fields reject.

### 4.2 Review boundaries

Every mutating action has this lifecycle:

```text
request → pure plan → render → synchronous review → apply → receipt
```

Review occurs before target mutation and outside any live barrier. A plan is
immutable, non-serializable, Engine-bound, and single-use. A Plan for an
existing target is process-generation-bound; a LaunchPlan is instead bound to
the exact executable snapshot and creates the generation on success. The
durable review transcript stores its canonical public summary and SHA-256, not
the opaque Plan.

A workflow is an ordered action graph, not one byte-complete Plan. Dynamic
facts establish mandatory review checkpoints:

```text
reviewed launch plan
→ observed process generation
→ reviewed library-load plan
→ observed module generation/base
→ reviewed hook-install plan
```

One CLI invocation may drive every checkpoint, but it emits each new Plan and
invokes the reviewer separately. Human mode prints the Plan and prompts.
Structured or non-interactive mutation requires `--yes`; multi-checkpoint
structured output requires `--format jsonl` and emits one plan record per
checkpoint followed by one terminal workflow report. `--yes` is recorded as
the review decision source and never suppresses Plan emission.

### 4.3 ActionStore

Every mutating instrumentation command requires an `ActionStore`. The stock
store is a private directory with owner-only permissions. It uses write-temp,
file-sync, atomic publication, directory-sync, and startup reconciliation.

Each action journal contains immutable intent, plan-summary digest, ordered
effect observations, terminal result when present, exact inverse material when
an exact inverse exists, an explicit non-reversible state otherwise, dependency
edges, provider identity, and process/module generations. Intents sync before
provider mutation. Effects sync before a live barrier or loader lease is
released and before a later dependent action. Results sync before recovery
ownership is released. Interior corruption fails closed; an incomplete trailing
publication is reconciled from its journal.

The store exposes reserve-idempotency, append-intent, append-effect,
append-result, list-pending, list-recoverable, load-handle, retire-target-gone,
and reconcile. It never edits a terminal record. Store capacity and paths are
explicit Engine configuration and appear in reports without exposing private
authentication material.

### 4.4 SessionStore

The stock `SessionStore` owns open capture directories, CAS publication,
manifests, sealing, listing, and recovery. ActionStore records and session
records cross-reference by digest and ID but remain independently verifiable.
A session cannot seal while an action journal affecting it is unbound or
pending. Neither store is the existing file `UndoStore`.

## 5. InstrumentationProvider contract

### 5.1 Capabilities

`InstrumentationCapabilities` is separate from `ProcessCapabilities` and is a
closed value containing:

- selector and launch strategy sets;
- attach, full-quiescence, cooperative-exclusion, retained-recovery, module
  enumeration, exact reads/writes, protection change, instruction pointers,
  and instruction-cache flush;
- allocation purposes, exact-address support, release support, page/alignment
  limits, per-allocation and aggregate capacity;
- library delivery strategy set and loader/initializer limits;
- loader-execution lease and loader-recovery support;
- hook architectures, hook modes, handler ABI versions, relocation profiles,
  and mitigation profiles;
- resident-agent protocol versions, capture support, maximum sessions, hooks,
  message bytes, queue entries, and payload bytes; and
- provider-specific native profile id.

Capabilities are captured when the provider is registered or handshakes. The
Engine validates internal cross-products and freezes them. A runtime operation
requires both an advertised capability and the corresponding applicable native
conformance profile.

### 5.2 Provider operations

```text
inspect_admission(target) -> TargetAdmissionSnapshot
observe_launch_inputs(request) -> LaunchObservationSet
launch(instruction) -> MutationOutcome<LaunchObservation>
resolve(selector) -> ProcessHandle
identify(handle) -> ProcessGeneration
snapshot(handle) -> ProcessSnapshot
acquire_barrier(handle, kind) -> BarrierGuard
retain_barrier(guard, reservation) -> RetainedBarrier
recover_actions() -> [ProviderRecovery]

allocation_candidates(handle, request) -> [MemoryCandidate]
allocate_exact(guard, candidate) -> MutationOutcome<AllocationObservation>
release_exact(guard, handle, expected) -> MutationOutcome<ReleaseObservation>

acquire_loader_lease(handle, instruction) -> Outcome<LoaderExecutionLease>
load_library(lease, instruction) -> MutationOutcome<LibraryLoadObservation>
finish_loader_lease(lease) -> MutationOutcome<LoaderLeaseObservation>
unload_library(lease, instruction) -> MutationOutcome<LibraryUnloadObservation>

install_hook(guard, instruction) -> MutationOutcome<HookInstallObservation>
remove_hook(guard, instruction) -> MutationOutcome<HookRemoveObservation>

start_agent(handle, instruction) -> MutationOutcome<AgentObservation>
agent_control(session, request) -> AgentControlObservation
stop_agent(session) -> AgentStopObservation
```

The Engine constructs public Plans and, only after review, derives a canonical
internal `ReviewedProviderInstruction` containing the Plan digest and exact
authorized provider operations. The instruction may cross only the private
provider boundary; it is not a public or reusable Plan and is never accepted
from a caller. Providers return observations and effects; they do not accept
source, choose policy, render reports, or declare success outside the typed
outcome.

### 5.3 Out-of-process protocol

The private provider protocol is a sequence of 4-byte big-endian length plus
canonical UTF-8 JSON frames, each at most `provider_message_bytes`. The first
exchange is:

```text
HostHello { protocol, nonce, product_version, expected_provider }
ProviderHello { protocol, nonce_echo, provider, capabilities, pid }
HostAccept { transcript_sha256, hmac_sha256 }
```

`hmac_sha256` is HMAC-SHA-256 over the canonical HostHello and ProviderHello
frames using an inherited random 256-bit one-time token. Each direction's
session key is HMAC-SHA-256 of that token over the canonical tuple
`("splice-provider-mac-v1", direction, accepted_transcript_sha256)`; both
peers then erase the token. The token is never placed in a command line,
environment variable, report, ActionStore, or SessionStore.

Subsequent envelopes contain protocol, session id when present, monotonically
increasing direction-local sequence, request id, operation tag, body schema id,
body, previous transcript SHA-256, and HMAC-SHA-256 over the canonical envelope
with the HMAC field omitted. The accepted frame advances the transcript digest.
Duplicate, skipped, reordered, unknown, oversized, noncanonical,
unauthenticated, or post-terminal frames close the channel and produce a typed
provider-protocol failure.

Artifacts larger than one JSON frame never travel as embedded bytes. The host
publishes them to its private immutable CAS and transfers a read-only inherited
file descriptor or platform handle plus digest, length, media type, and ABI.
The provider reads exactly the declared length, rejects short or trailing data,
recomputes the digest, and rejects mutable-identity disagreement before use. An
out-of-process provider consumes only the verified bytes from that read and
never reopens the path. An in-process extension receives an immutable
`ByteSource` and performs the same length/digest/media/ABI checks.

The CLI spawns a provider with an inherited socketpair or named-pipe handle and
one-time secret delivered only through inherited private state. The provider
opens no listener. Detached sessions transfer the authenticated endpoint and
store lease to a private supervisor process listed in the provider manifest;
later `splice` commands use a fresh random 256-bit control token in the
owner-only SessionStore, prove it with nonce-bound HMAC-SHA-256, and rotate it
after each successful connection. A replay, stale token, or failed proof closes
the endpoint before any session operation.

An in-process extension implements the same operation/state model through the
trait and must pass the same component conformance cases through an adapter. It
does not use wire framing but cannot weaken sequencing or capability rules.

## 6. Target admission, launch, and attach

### 6.1 Common model

`TargetAdmissionSnapshot` contains provider, platform, architecture, requested
operation set, caller identity class, target ownership class, process state when
present, executable identity/signing facts, platform protection facts, live
probe observations, and one closed verdict per requested capability:
`admitted`, `unavailable`, or `denied` with stable reason.

Planning uses only captured facts. A provider denial cannot be overridden by a
CLI force flag. Splice never changes SIP, boot arguments, kernel policy, or
system-wide security settings.

### 6.2 Launch

`LaunchRequest` binds executable file state and digest, argument vector,
environment map, working directory, architecture, initial stop policy,
credential provider, instrumentation-profile digest, agent/library artifacts,
and one strategy:
`ordinary`, `load_command`, or `dyld_environment` on Darwin.
Initial stop policy is exactly `at_entry`, `at_main`, or `running`.

`LaunchPlan` is file/process-generation independent. It contains exact file
transformation and signing subplans when applicable, launch environment,
provider identity, expected admission facts, and expected initial process
state. A successful `LaunchReceipt` creates the process generation and initial
module snapshot used by later Plans. Launch failure never fabricates a process
handle.

`load_command` composes the existing reviewed Mach-O structural-edit and
credential-finalization path before launch. `dyld_environment` is admitted only
when the captured hardened-runtime, allow-DYLD, and library-validation facts
permit the exact library. Equal executable bytes in a later launch still yield
a different process generation.

### 6.3 Attach

`AttachRequest` binds selector, provider, instrumentation-profile digest,
requested capabilities, and optional expected executable identity. Planning
resolves one process, captures a fresh generation and module snapshot, and
refuses zero or multiple candidates. Apply re-resolves and requires generation
equality before creating a session.

### 6.4 Darwin admission profile

The Darwin snapshot carries SIP state, platform-binary bit, hardened-runtime
bit, get-task-allow, caller debugger entitlement, target library-validation
state, allow-DYLD-environment state, disable-library-validation state, signing
team/designated requirement, architecture/arm64e, task-port probe result, and
source (`static`, `live`, or `provider_attested`) for each fact.

With SIP enabled, a platform binary is denied for attach/injection. The Darwin
v1 profile admits attach only when caller and target are the same effective
user; cross-user control requires a future profile with a separate
authorization surface. An existing third-party hardened target without
task-port admission is denied. A controlled or re-signed target is admitted
only when exact signing and entitlement facts plus the live task-port probe
support the requested strategy. Static load-command launch remains separately
admissible after reviewed signing.

## 7. Memory allocation

`MemoryAllocationRequest` contains process generation, purpose (`data`,
`loader_input`, `trampoline`, `executable_code`, or `shared_control`), nonzero
length, power-of-two alignment, address policy, backing/share policy, initial
bytes policy, protection lifecycle, lifetime, and idempotency key.

Backing/share policy is exactly `private_anonymous` or `shared_control`.
`shared_control` purpose and backing must occur together; every other purpose
uses `private_anonymous`.

The public address policy is closed to `anywhere`,
`near { module_generation, rva, max_distance }`, or
`exact { address }`. Initial bytes are `zeroed` or
`artifact_slice { artifact_ref, offset, length }`. Protection lifecycle is
`read_write`, `read_only_after_write`, or `read_execute_after_write`;
executable purposes require the last arm, and no arm permits simultaneous write
and execute. Internal hook/loader allocations use the same variants and bind
their exact bytes through the parent reviewed Plan.

All arithmetic is checked. Length rounds to pages only in the Plan and the
reviewed candidate shows requested and mapped lengths. Candidate addresses are
canonical, page aligned, overflow free, sorted by distance then address, unique,
and bounded. Each candidate contains the complete expected mapping delta,
backing/inheritance/share facts, guard pages, and protection sequence.

Persistent writable-executable memory is rejected. Executable content follows
unmapped → read/write non-executable → exact write/readback → read/execute
non-writable → cache flush. Darwin MAP_JIT or entitlement-dependent paths are
distinct capability/profile arms and never inferred from ordinary allocation.

Success returns `MemoryHandle` with allocation id, generation, exact mappings,
content digest, purpose, lifetime, and dependency set. Lifetimes are
`action_scoped`, `owned`, or `resident_until_exit`. `action_scoped` memory is
never exposed to target code after the action. `owned` release requires an empty
modeled dependency set, zero active invocation epochs, IP exclusion for
executable ranges, exact content/protection preimages, and observed mapping
disappearance. Memory whose address escaped the modeled ownership graph becomes
`resident_until_exit`; Splice never claims unknown pointer absence.

## 8. Library delivery

`LibraryArtifact` binds exact bytes, SHA-256, media type, format, architecture,
code-signing identity, install identity, and closed dependency inventory.
`LibraryLoadRequest` binds artifact, process generation, delivery strategy,
initializer policy (`run_bounded` or `forbid` where the platform can prove it),
timeout, unload policy, temporary-memory limits, and idempotency key.

The strategies are `launch_load_command`, `launch_dyld_environment`,
`attach_resident_agent`, and `attach_backend_loader`. A strategy absent from
capabilities or target admission rejects before Plan.

Attach-time loading is not performed under an ordinary patch barrier. Its
reviewed state machine is:

1. revalidate process/admission/module snapshot;
2. durably append intent and prepare provider recovery;
3. acquire the provider's loader-execution lease, which designates exactly one
   control executor and freezes competing provider operations without claiming
   full target quiescence;
4. allocate only reviewed temporary state;
5. invoke only the platform loader operation named by the Plan;
6. enforce timeout and classify returned, nonreturning, target-gone, and
   unknown-effect outcomes;
7. durably append the execution observation, then finish the loader lease only
   when the provider proves the control executor retired; otherwise transfer
   the live lease to recovery ownership and classify the effect unknown;
8. acquire a full snapshot barrier, enumerate modules, and require one module
   matching the exact reviewed artifact identity plus exactly the reviewed
   preexisting/new dependency delta;
9. clean temporary state where proven safe; and
10. persist the terminal receipt before releasing recovery ownership.

Success never follows solely from a loader return value. It returns
`LibraryHandle` bound to observed module generation/base/mappings and modeled
dependencies. Already-loaded equal identity is a separate idempotent result;
same install identity with different bytes is conflict.

Unload requires a fresh reviewed Plan, a loader-execution lease, no dependent
hooks/agents/allocations, zero active library invocation count where supported,
and a declared `unloadable` contract. Otherwise the handle is
`resident_until_exit`. Even a successful unmap never claims to reverse
constructors, threads, callbacks, class registration, TLS, I/O, or
process-global state. If an initializer ran before a later workflow failure,
the workflow is `partial` even when mappings were removed.

## 9. Hooks and relocation

### 9.1 Hook request and ABI

V1 supports `before` entry hooks only. `after`, `replace`, suppression of the
original function, and arbitrary control-flow return values reject at request
validation.

`HookInstallRequest` binds process/module generation, symbol or exact locator,
handler library generation and symbol, `splice-hook-handler/v1`, architecture,
declared readable/writable register masks, relocation limits, candidate limits,
and idempotency key. A handler library must already be observed; loading it is a
separate reviewed action.

`HookLocator` is closed: either `symbol { name }` or
`rva { module_generation, offset }`. Resolution must produce exactly one
executable address in the bound module generation. Raw virtual addresses,
pattern scans, demangled-name guesses, and ambiguous symbol matches reject.

The C-layout `HookContextV1` starts with `{struct_size:u32, abi_major:u16,
abi_minor:u16, arch:u32, flags:u32}` followed by hook id, invocation id, target
address, thread id, register-block pointer/length, decision-block
pointer/length, and reserved-zero fields. Architecture-specific register blocks
have generated offset/size constants and closed writable masks. The handler
entry is `u32 splice_hook_v1(HookContextV1*)`; the only valid return is
`continue = 0`.

The handler may mutate only admitted register fields and bounded decision bytes.
It may not unwind, throw, longjmp, retain context pointers, or return while a
foreign exception is active. ABI violation is target-code failure, increments
an agent fault counter when observation remains possible, and never becomes a
Splice success. Stack alignment, red zone, vector state, errno/thread state,
PAC/BTI/CET/CFG, and clobber preservation are architecture-profile fields.

Per-thread recursion is suppressed: a nested entry bypasses the handler,
executes relocated instructions, and records a recursion counter. Each hook has
an active-invocation epoch covering handler entry through the final branch to
the undisplaced continuation.

### 9.2 Relocation

Relocation is pure and bounded. It consumes exact original bytes/address,
trampoline address, continuation address, architecture profile, and limits and
returns decoded displaced instructions, relocation explanation, exact emitted
bytes, fixups, veneers, and scratch/clobber effects.

ARM64 covers fixed-width non-PC-relative instructions, B/BL, conditional and
compare/test branches, ADR/ADRP, and literal loads. x86-64 covers whole decoded
instructions, relative calls/jumps/conditions, and RIP-relative operands.
Anything outside the closed subset rejects. Re-decoding emitted bytes must
reproduce the explanation and semantic targets. ARM64e/PAC, BTI, CET, CFG,
unwind, and exception-entry requirements are explicit admitted/unsupported
profile facts.

### 9.3 Install and remove

`HookInstallPlan` contains exact target preimage, displaced instructions,
finite canonical allocation candidates, exact trampoline/relay/entry bytes,
handler identity, ABI effects, mappings/protections, decision reads, barrier,
IP exclusion ranges, dependency graph, and ordered install/rollback operations.

Install revalidates under the selected patch barrier, arms recovery, allocates
and writes non-executable trampoline state, readbacks, applies final RX
protection and cache flush, proves IP exclusion, writes/readbacks/flushes the
entry patch, persists receipt, then releases the barrier. Rollback restores the
entry before releasing any reachable allocation.

`HookHandle` persists exact original/installed bytes, mappings, handler and
module generations, allocations, action ids, and active-epoch location.
Removal is separately planned and reviewed. It requires installed-byte equality,
zero active invocation epoch, IP exclusion across entry/trampoline/relay/handler,
and unchanged generations. It restores/readbacks/flushes the entry before
clearing and releasing trampoline state. A suspended active invocation causes
bounded refusal. A possibly reachable allocation is retained, never freed.

Overlapping recognized hooks conflict unless the canonical request is the same
idempotent action. An unrecognized preexisting patch rejects; v1 has no implicit
hook chaining.

## 10. Resident agent and capture

### 10.1 Agent identity and control

The injected agent artifact is digest pinned, signed where required, and
described by `AgentArtifact {protocol, arch, media_type, abi, sha256, len}`.
Agent hello echoes artifact identity, process generation, module generation,
provider identity, random challenge, and capability limits. Mismatch stops
before hook installation.

Agent control uses the provider channel and closed commands: hello, configure,
install_binding, remove_binding, start_capture, stop_capture, status, drain, and
shutdown. There is no eval, arbitrary address call, ambient file access, clock
request, or unbounded response. Unknown commands/fields reject.

### 10.2 Capture profile

`InstrumentationProfile` contains profile id/version, target admission
requirements, agent artifact, ordered hook bindings, payload policy, queue and
session limits, decoder/ruleset identity, redaction policy, and stop policy.
Bindings are unique and sorted by stable hook id and contain locator, mode,
handler/extractor identity, required/optional disposition, and one closed
`CaptureSpec`:

```text
none
registers { names: sorted unique register names }
bounded_memory {
  base_register,
  signed_offset,
  length: constant | register,
  max_len,
  media_type
}
```

A bounded-memory capture performs one checked read from the entry snapshot. It
does not chase pointers, call target code, allocate, or retry, and it cannot
exceed the binding or session payload limit. V1 media types are a generated
closed built-in set.
V1 uses only built-in capture ABI, decoder, and ruleset identities; unknown or
third-party execution identities reject.

### 10.3 Callback and backpressure

The hot callback path uses preallocated per-thread slots and a bounded MPSC
queue. It stamps sequence reservation, hook id, thread id, invocation id,
monotonic timestamp supplied by the agent, payload state, and bounded bytes,
then enqueues. It performs no file I/O, dynamic loader work, network I/O,
unbounded allocation, schema parsing, or report rendering.

Payload states are:

```text
absent
retained { artifact_ref, full_len }
metadata { full_len, digest }
truncated { artifact_ref, captured_len, full_len }
failed { reason }
```

Queue-full, slot exhaustion, callback fault, payload-copy failure, provider
disconnect, and shutdown cutoff produce explicit loss spans. A failed payload
state is the accounting fact and has no duplicate loss record. Events and loss
spans together cover every reserved sequence exactly once.

### 10.4 Action boundaries

Before a target mutation, the Engine asks the agent to enqueue
`action_begin` in the same sequence domain as events, drains through that
marker, and durably records `begin_marker_agent_seq`. After mutation and target
resume, it enqueues `action_end`, drains through that marker, and records
`end_marker_agent_seq`. The action effect binds both marker records and
sequences. Excluding the markers themselves, an event before the begin sequence
is before the action, one between the two sequences is during it, and one after
the end sequence is after it. A missing end boundary makes the action/session
incomplete. If capture was stopped, the boundary is explicitly
`not_applicable`. Analysis never infers an action side from timestamps.

## 11. Raw session artifact

### 11.1 Directory and files

```text
<session>/
  OPEN.json                 present only while open or recovering
  session.ndjson            ordered records
  objects/<sha256>          immutable payload/action/provider artifacts
  SESSION.json              sealed manifest, published last
```

Objects publish through temporary write, file sync, digest/length verification,
hard-link or atomic no-replace final publication, directory sync, temporary-name
unlink, and directory sync. Startup reconciliation marks references from the
durable ledger/action journal before removing unreferenced temporary or final
objects. A sealed manifest lists exactly every final object and every package
file except itself.

### 11.2 Records

The first record is `session_header`; the last sealed record is `footer`.
Between them the closed record set is `target_snapshot`, `module_snapshot`,
`action_intent`, `action_effect`, `action_result`, `event`, `loss`, and `marker`.
Every record contains schema, session id, producer id, global sequence, and
record id derived from the canonical complete record with `record_id` omitted.
The ledger assigns global sequence only at durable append, producing one
contiguous zero-based sequence across all producers. Record bodies deny unknown
fields.

Events additionally contain agent sequence, monotonic timestamp, hook id,
thread id, invocation id, module generation, and payload state. Marker records
carry the action-boundary facts from §10.4. Loss contains exact inclusive
agent-sequence range, scope, reason, count, and optional hook ids. Global and
agent sequences are strictly
increasing in their respective domains with no duplicates.

The header binds provider, process generation, initial modules, profile,
capabilities, agent identity, action-store identity, limits, clock description,
and initial admission snapshot. The footer binds terminal target state, final
modules, record/event/loss/object counts, last sequences, pending actions,
capture completion, and incomplete reasons.

### 11.3 Seal equations

Seal requires no unbound object or action journal, exact object closure, one
footer, and these equations:

```text
reserved_agent_sequences = events + agent_markers + loss_span_counts
events = payload_absent + retained + metadata + truncated + failed
payload_artifact_references = retained + truncated
pending_actions = action_intents - terminal_action_results
manifest_objects = exact final objects directory
```

A clean seal requires zero pending actions and a drained capture. Stop during a
pending action seals only as incomplete after durable recovery ownership is
recorded. Target disappearance is a terminal incomplete reason, not a clean
drain. Sealing and validation never modify raw bytes.

## 12. Independent raw verifier

`splice instrument session check` reads only the package, generated schemas,
and declared built-in identities. It does not trust provider, agent, action
store, or producer verdicts. It returns:

```text
sound
incomplete
damaged
unsupported_schema
```

The generated rule catalog owns independent opinions for:

1. schema/version and unknown-field closure;
2. first-header/last-footer and record ordering;
3. session, record, producer, sequence, and process/module identities;
4. profile, provider, capability, admission, agent, and limit bindings;
5. canonical artifact paths, digest/length/media/ABI, and exact closure;
6. event hook/inventory/module resolution;
7. payload-state and artifact consistency;
8. loss nonoverlap, exact coverage, and no failed-payload double counting;
9. action-marker ordering/bindings, footer equations, and completion
   cross-products;
10. action identity, lifecycle, order, plan/effect/result bindings;
11. allocation candidate/effect/release and W^X observations;
12. library artifact/module/load/unload/dependency observations;
13. hook relocation/install/remove/dependency/active-epoch observations;
14. provider protocol transcript and recovery observations;
15. manifest/session/public action-record projections; and
16. no analysis/report provenance inside the raw ledger.

Each opinion has stable generated code, severity, message, and one deliberately
invalid fixture per independent rejection clause. `--allow-incomplete` may
change only CLI exit handling for declared incomplete opinions; it never
downgrades damage, unsupported schema, or any actuation identity/safety rule.
The offline verifier never opens or trusts the private ActionStore. Every public
action fact needed for verification is copied into the raw ledger and
digest-bound to its corresponding intent, effect, result, and artifact.

## 13. Analysis, report, redaction, and diff

### 13.1 Analysis package

Analysis refuses damaged or unsupported raw input. It accepts sound or
incomplete input and preserves the exact fresh raw-verifier verdict and ordered
issues in header and manifest.

`ANALYSIS.ndjson` contains one header, decoded records, and edges. The manifest
binds raw manifest SHA-256, built-in decoder/ruleset bytes and versions,
analysis config, redaction profile, engine identity/limits, execution SHA-256,
all package file digests, and exact package closure. Every record repeats raw
manifest and execution identities. Validation reruns raw verification and
recomputes every identity without changing raw bytes.

V1 decoding is deterministic and built in. Retained/truncated bytes produce
either a canonical decoded value or a typed decode failure; absent, metadata,
and failed payloads are never decoded. Decode failure produces exactly one
coverage edge and no invented value.

### 13.2 Edges and support

The closed edge set is `episode`, `pair`, `flow`, `hook_activity`,
`module_lifecycle`, `anomaly`, `coverage_gap`, `actuation`, and `index`. Every
non-coverage edge has at least one supporting raw/decoded/action record. Every
member list is global-sequence ordered. Canonical keys use only explicitly
redaction-safe semantic identity fields and are byte-identical under safe and
none redaction.

Coverage classes are `silent_hook`, `payload_unavailable`, `decode_failed`,
`capture_loss`, and `incomplete_action`. Anomaly classes are `aborted`,
`retry`, `error`, `rejection`, `provider_fault`, and `handler_fault`. Unknown
classes invalidate the package.

### 13.3 Report projection

The investigator report is a pure projection of typed edges plus raw
provenance; it does not independently recompute analytical claims. It includes
target/provider/profile identity, raw verdict/issues, coverage, hook activity,
module lifecycle, action timeline, anomalies, correlations, and recovery state.
Every displayed claim cites supporting IDs.

### 13.4 Redaction and diff

Redaction profiles are `safe@1` and `none`. Safe redaction applies before report
projection but after semantic keys are derived from admitted safe fields.
Secrets never appear in keys, index facets, diagnostics, or action summaries.

Diff inputs must each pass complete package validation and have equal analysis
execution identity. Rows align by kind plus canonical key, show added/removed/
changed bodies and support, and omit unchanged rows. Mismatched decoder,
ruleset, config, limits, or redaction identity rejects as not comparable.

## 14. Instrumentation reports and statuses

Every `splice instrument` command emits `splice.instrumentation.report/v1`.
The common envelope contains schema, command, status, diagnostics, provider,
session/action ids, review transcripts, and one closed payload arm.

Statuses are `ready`, `no_change`, `applied`, `rolled_back`, `partial`,
`incomplete`, `sound`, `damaged`, `unsupported_schema`, `not_comparable`,
`rejected`, `target_gone`, and `unsupported`. Payload arms are `info`,
`launch`, `attach`, `memory_allocate`, `memory_release`, `library_load`,
`library_unload`, `hook_install`, `hook_remove`, `capture_start`,
`capture_stop`, `review_checkpoint`, `session_stop`, `session_list`, `session_show`,
`session_check`, `session_report`, and `session_diff`.

A JSONL review-checkpoint record carries only the canonical public Plan summary,
Plan digest, checkpoint ordinal, and pending review source. It never serializes
the opaque Plan or a provider instruction. The final record carries the
terminal workflow payload.

Structural validation owns closed fields and variants. Semantic validation
independently checks request/plan/report/action digests, status/effect/residual
cross-products, provider capability and protocol identity, process/module
generations, candidate membership, action ordering, dependency graph, mapping
and byte observations, barrier/recovery transitions, session bindings, and pure
report projection. Renderers consume only validated typed reports.

A normal info, review-checkpoint, session-list, session-show, or session-report
payload has status `ready`. A normal mutating payload has `no_change` exactly
when `changed` is false, `incomplete` exactly for a changed incomplete capture
or session stop, and `applied` otherwise. Session-check status exactly equals
its verdict. Session-diff has `no_change` for zero changed rows and `ready`
otherwise. Normal payloads carry no command diagnostics; verifier issues remain
inside the session-check payload.

A failure payload has kind `failure`, repeats the outer command, and carries
only a failure stage, an effect classification, and the digests that already
exist at that stage. Request, verification, analysis, and comparison failures
carry no request, Plan, or receipt digest. Provider-discovery and planning
failures carry only the request digest. Review failures carry request and Plan
digests. Apply and recovery failures carry request, Plan, and receipt digests.
No absent digest may be fabricated to complete this shape.

Rejected, unsupported, and not-comparable failures have `no_effect`;
not-comparable is only a session-diff comparison failure. Rolled-back failures
are mutating recovery failures with `rolled_back`. Partial failures are
mutating apply or recovery failures with `unknown_effect`. Target-gone failures
are mutating planning, apply, or recovery failures with `target_gone`. Every
failure has at least one error diagnostic. A review, apply, or recovery stage
is valid only for a mutating command; verification, analysis, and comparison
belong only to session-check, session-report, and session-diff respectively.

A normal mutating report names the selected provider, resulting session, durable
action, and a terminal approved review whose Plan digest and action kind match
the payload. Review checkpoint reports name the selected provider and repeat
their one pending review exactly. Session-show, session-check, and
session-report name their session; info, session-list, and session-diff carry
no outer provider, session, action, or review context.

Failure context is stage-exact. Request and provider-discovery failures have no
selected provider, action, or review. Planning failures name the provider but
have no action or review. Review failures name the provider and end in a
matching declined review. Apply and recovery failures name the provider and
durable action and end in a matching approved review. Offline verification,
analysis, and comparison failures have no provider, action, or review. Every
session-bound command names its session at every reportable stage.

Unknown provider fields, omitted preimages, substituted candidates, success
without required observations, false rollback, false unload reversal, or a
renderer-derived fact invalidates the report.

## 15. Public CLI and toolkit

### 15.1 CLI

The single command tree is:

```text
splice instrument info
splice instrument launch --profile PROFILE [--detach] [--yes] -- EXECUTABLE [ARG...]
splice instrument attach --profile PROFILE [--detach] [--yes] PROCESS
splice instrument memory allocate --session ID --request REQUEST [--yes]
splice instrument memory release --session ID --allocation ID [--yes]
splice instrument library load --session ID --artifact PATH --request REQUEST [--yes]
splice instrument library unload --session ID --library ID [--yes]
splice instrument hook install --session ID --request REQUEST [--yes]
splice instrument hook remove --session ID --hook ID [--yes]
splice instrument capture start --session ID [--yes]
splice instrument capture stop --session ID [--yes]
splice instrument session list
splice instrument session show ID
splice instrument session check ID [--allow-incomplete]
splice instrument session report ID --output DIR
splice instrument session diff LEFT RIGHT
splice instrument stop ID [--yes]
```

`PROCESS` uses the existing selector grammar. PROFILE and REQUEST name files
whose bytes must already be canonical JSON and validate against the generated
schema; the CLI does not reinterpret noncanonical input before identity
derivation. Human destructive commands prompt unless `--yes`. JSON/JSONL or
noninteractive destructive commands require `--yes`. Provider binaries have no
public help or direct invocation contract.

Command availability does not disappear from help. When no applicable provider
is installed, commands return `unsupported` with provider-unavailable
diagnostics. `instrument info` lists provider manifests, executable digest
verification, capabilities, runtime gates, agent artifacts, store locations,
and active sessions without exposing secrets.

Exit status is 0 for sound success/no-change, 1 for rejected/incomplete/damaged
or operational failure, and 2 for CLI/schema misuse. `--allow-incomplete`
changes 1 to 0 only for a checked session whose sole non-sound opinions are
declared incomplete.

### 15.2 Toolkit

`splice` adds:

```text
InstrumentationEngineBuilder
  .provider(in_process_provider)
  .provider_manifest(path)
  .action_store(store)
  .session_store(store)
  .limits(limits)
  .build()

InstrumentationEngine
  .info()
  .plan_launch(request)
  .apply_launch(plan, reviewer)
  .plan_attach(request)
  .apply_attach(plan, reviewer)
  .open_session(id)
  .list_sessions()
  .recover()
  .verify_session(path)
  .analyze_session(path, config)
  .diff_analysis(left, right)

InstrumentationSession
  .plan_allocate(request) / .apply_allocate(plan, reviewer)
  .plan_release(id) / .apply_release(plan, reviewer)
  .plan_load_library(request) / .apply_load_library(plan, reviewer)
  .plan_unload_library(id) / .apply_unload_library(plan, reviewer)
  .plan_install_hook(request) / .apply_install_hook(plan, reviewer)
  .plan_remove_hook(id) / .apply_remove_hook(plan, reviewer)
  .plan_start_capture() / .apply_start_capture(plan, reviewer)
  .plan_stop_capture() / .apply_stop_capture(plan, reviewer)
  .plan_stop() / .apply_stop(plan, reviewer)
```

All Plans and handles are Engine/session-bound, non-cloneable where ownership is
linear, non-serializable, and rejected across foreign Engine/session instances.
Bindings expose opaque handles and typed immutable views; they never expose raw
provider handles or authentication tokens.

## 16. Limits and diagnostics

Generated limits include default, minimum, maximum, identity-bearing status,
and report field. Initial defaults are:

| Limit | Default |
|---|---:|
| provider message bytes | 16 MiB |
| provider operations per workflow | 128 |
| allocation candidates | 64 |
| one allocation | 64 MiB |
| aggregate owned allocation | 256 MiB |
| displaced hook bytes | 64 |
| trampoline bytes | 4096 |
| hooks per session | 4096 |
| active sessions | 16 |
| agent queue entries | 65536 |
| one payload | 16 MiB |
| one session object | 64 MiB |
| loader initializer time | 5 s |
| hook removal wait | 1 s |
| analysis decoded output | 16 MiB per event |

Overflow, zero where nonzero is required, max+1, and inconsistent aggregate
limits reject before provider access. Runtime-dependent limits are folded into
action, session, and analysis execution identities.

Stable diagnostic families cover request/schema, provider discovery/protocol,
target admission, stale generation, capability unavailable, review decline,
store/recovery, allocation, loader/initializer, hook relocation/platform/ABI,
capture/loss, session closure, raw verification, analysis validation,
redaction, diff comparability, and retirement boundary. Provider-local detail
codes remain nested and cannot shadow Engine codes or choose verdicts.

## 17. Generated authority and conformance

Canonical prose remains clean and byte-locked. `compile.py` reconstructs the
external authority declarations for every schema, surface, toolkit operation,
component method, capability profile, limit, diagnostic, rule, CLI form,
binding entry point, and case family, then generates Rust constants, JSON
Schemas, report predicates, catalogs, profiles, CLI mirrors, and case manifests.
Existing generated v1 authority remains; the new rows are additive or have
explicit semantic-ID migration entries where §20/§29 and `splice-as-agent.md`
wording is replaced. Inline authority metadata is forbidden.

Minimum conformance families are:

| Family | Required positive and negative evidence |
|---|---|
| F01 authority/version | old reports still validate; instrumentation report rejected by old schema; no unapproved migration |
| F02 provider discovery | active/gated manifest valid; PATH/env/working-directory, missing supervisor, and executable digest mismatch rejected |
| F03 provider protocol | valid handshake/frame MAC/artifact transfer/detached reconnect; bad token/nonce/version/sequence/canonical JSON/size/MAC/artifact/replay/post-terminal rejected |
| F04 extension equivalence | virtual wire and in-process providers yield semantically identical operation bodies/verdicts; only declared placement identity differs |
| F05 launch | ordinary/load-command/DYLD admitted cases; signing, environment, no-process, equal-image relaunch negatives |
| F06 attach/admission | controlled same-user target admitted; zero/multiple/stale/cross-user/platform/SIP/task-port negatives |
| F07 allocation | every purpose and lifecycle; zero/overflow/rounding/substitution/RWX/capacity/release-dependency negatives |
| F08 library load | every strategy and loader-lease arm; identity/dependency/initializer/timeout/nonreturn/module-absence/conflict negatives |
| F09 library unload | unloadable success; live dependency/active invocation/foreign bytes/nonreversible-state negatives |
| F10 relocation ARM64 | every admitted instruction class and every unsupported/overflow/mitigation class |
| F11 relocation x86-64 | every admitted instruction class and every unsupported/overflow/CET/CFG class |
| F12 hook install | exact symbol/RVA install; ambiguous/raw locator, occupied candidate, partial instruction, readback, cache, IP, overlap, stale, crash negatives |
| F13 hook ABI | valid context; size/version/mask/return/unwind/recursion/fault cases |
| F14 hook remove | clean inverse; active epoch, IP, foreign byte, dependency, crash, target-gone cases |
| F15 action store | idempotency, every crash point, corrupt interior/tail, pending/recovery/target-gone cases |
| F16 agent protocol | hello/config/start/drain/stop; identity, unknown field/command, replay, disconnect cases |
| F17 capture | every CaptureSpec and action boundary; event/payload states; queue/slot/callback/copy/disconnect/shutdown losses and no double accounting |
| F18 ledger/CAS | canonical object, deduplicated references, exact closure, crash publication, orphan recovery, record identity/ordering and seal equations |
| F19 raw verifier | one invalid fixture for every independent rule clause; mutation removal makes its fixture pass and fails the gate |
| F20 analysis | decode success/failure, edge support, deterministic rebuild, raw immutability, closure, tamper cases |
| F21 redaction/report | safe/none key identity, secret leak negatives, pure projection and unsupported recomputation cases |
| F22 diff | one-change alignment, added/removed, unchanged omission, every comparability mismatch refused |
| F23 CLI/toolkit | every command/operation valid/rejected arm, prompt/yes/JSONL review checkpoints, planned stop, opaque handle misuse, provider unavailable |
| F24 native Darwin ARM64 | controlled launch/attach/allocation/load/hook/capture/stop plus SIP and mitigation matrix |
| F25 gated profiles | complete schemas/capabilities false/no applicable native skip or inferred support |
| F26 retirement | dependency/import/public name/schema/help/fixture/runtime discovery scans find no Refrida authority |

Every normative rule declaration names at least one case. Every independent
rejection clause has a deliberately invalid fixture. Family rows are a minimum,
not a substitute for clause-level mapping. The conformance verifier selftest
removes or weakens representative schema, semantic, native-profile, and
retirement checks and requires the corresponding cases to fail.

## 18. Execution order and gates

These slices execute as one contract:

1. **Canonical absorption and generation.** Land all schemas, surfaces, rules,
   profiles, diagnostics, limits, CLI/toolkit/component catalogs, report
   predicates, semantic migrations, and complete valid/invalid corpus.
   *Stop:* any runtime implementation begins while a format/verifier surface is
   absent or existing `splice.report/v1` changes.
2. **Portable model and stores.** Implement types, semantic validators,
   ActionStore, SessionStore, raw verifier, analysis, rendering, diff, and
   virtual provider/agent. *Stop:* a fixture passes only after adding a force or
   unchecked path, weakening closure, or inventing a new verdict.
3. **Pure allocation/relocation planning and lifecycle.** Implement canonical
   candidates, ARM64/x86-64 relocation, workflow checkpoints, allocation,
   library, and hook state machines against the virtual provider. *Stop:* apply
   synthesizes an unreviewed address/byte/strategy or crash recovery loses a
   reachable effect.
4. **Single CLI and private component protocol.** Implement command tree,
   manifest discovery, wire protocol, extension adapter, private supervisor,
   JSONL review stream, packaging, and boundary checks. *Stop:* a private binary
   acquires a public CLI or ambient discovery path.
5. **Darwin ARM64 native implementation.** Implement provider, agent, admission,
   signing integration, launch/attach, allocation, loading, hooks, capture, and
   recovery. *Stop:* a capability becomes true before its complete native case
   family passes or a SIP-protected target is treated as injectable.
6. **Retirement and release closure.** Remove temporary research imports, build
   SBOM/provider manifests, run all scans, package one CLI plus private
   components, and verify extracted bundles. *Stop:* any bundle needs the
   Refrida checkout or resolves a provider by ambient search.

Required commands become:

```text
python3 spec/compile.py generate
python3 spec/compile.py check
python3 spec/conformance/verify.py check
python3 spec/conformance/verify.py selftest
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo run --locked -p xtask -- boundary-check
cargo run --locked -p xtask -- instrumentation-conformance --profile portable
cargo run --locked -p xtask -- instrumentation-crash-matrix
cargo run --locked -p xtask -- instrumentation-report-differential
cargo run --locked -p xtask -- instrumentation-retirement-check
cargo run --locked -p xtask -- ci-native --job darwin-aarch64
cargo run --locked -p xtask -- package-verify
mise run ci
```

CI adds portable instrumentation jobs and a Darwin ARM64 controlled-target job.
Gated host jobs validate package/schema/profile honesty but do not advertise or
skip an applicable runtime capability. Release verification extracts each
bundle into a clean temporary directory, verifies provider/agent digests and
SBOM, runs `splice instrument info`, validates both report schemas offline, and
proves no dependency on the source checkout.

## 19. Global stopping criteria

Implementation is not complete if any of these is true:

- existing Splice v1 schema or behavior is weakened;
- instrumentation capability is reachable through generic Process edits;
- provider or agent discovery is ambient;
- a private binary exposes an independent user CLI;
- planning mutates the target or apply invents unreviewed state;
- a dynamic library load and dependent hook share one impossible byte-complete
  pre-load Plan;
- loader execution is mislabeled as full quiescence or clean rollback;
- persistent RWX memory is accepted;
- an allocation with escaped ownership is claimed safely released;
- loader return without exact module observation is success;
- constructor/global effects are claimed undone by unload;
- an unsupported instruction or mitigation is relocated optimistically;
- a handler may unwind or return arbitrary control flow through the v1 ABI;
- hook removal can race an active invocation or frees reachable code;
- event/loss ranges fail exact accounting or payload failure is counted twice;
- a session seals clean with pending actions, unbound objects, or undrained
  capture;
- the raw verifier trusts producer/provider verdicts;
- analysis modifies raw bytes, accepts damaged input, or emits unsupported
  claims;
- report rendering recomputes analytical facts absent from typed edges;
- redaction changes canonical semantic keys or leaks a secret;
- diff accepts unequal execution identity;
- a capability bit is true without applicable native conformance;
- a new error/verdict/force path exists only to make a fixture pass; or
- any production, conformance, package, help, schema, or runtime path requires
  or claims compatibility with Refrida.
