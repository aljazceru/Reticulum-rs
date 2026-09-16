# Remaining Implementation Gaps — Status

All gaps listed below are implemented and covered by tests. This file is
kept as the record of what was closed and where each piece lives.

## 1. Resource cancellation ✅

- `src/resource/outbound.rs`
  - `OutgoingResource::cancel(&mut self, link) -> ResourceTx` builds the
    `RESOURCE_ICL` packet and stops advertising/transferring.
- `src/resource/manager.rs`
  - `cancel_outbound(&mut self, link, hash)` marks outgoing transfers
    `Failed`, sends `RESOURCE_ICL`, and emits a `ResourceEvent`.
  - `cancel_inbound(&mut self, link, hash)` does the receiver-side cancel
    with `RESOURCE_RCL`.
  - Bug fixed on the way: receiver-built cancel/reject packets were sent
    unencrypted (`raw_packet`); peers decrypt them, so they now use
    `context_packet` (Python `Packet.pack` only leaves resource parts and
    proofs unencrypted).
- `src/transport.rs`
  - `cancel_resource(&self, link_id, hash)` sends the cancel and falls
    back to the receiver-side cancel when nothing is outbound.
  - `send_resource*` now returns the full 32-byte resource hash (the same
    hash used in resource events and accepted by `cancel_resource`). This
    also fixes the LXMF router's completion tracking, which compared event
    hashes against a truncated hash.
- `reticulum-actor`
  - `Action::CancelResource` calls the real `transport().cancel_resource`.
  - `Action::SetResourceStrategy` with an empty link id configures the
    transport-level default strategy (`set_default_resource_strategy`) so
    inbound resources can be accepted without knowing the link id.
- Tests: `tests/resource_transfer.rs`
  (`sender_cancel_fails_both_ends_of_a_transfer`,
  `receiver_cancel_fails_sender_transfer`),
  `reticulum-actor/tests/integration.rs`
  (`resource_offer_accept_and_cancel`).

## 2. LXMF transport-encryption selection ✅

- `lxmf/src/message.rs`
  - `LXMessage::destination_type` (Python `__destination.type`, defaults
    to `Single`) drives `determine_transport_encryption()`:
    `GROUP → Aes128`, `SINGLE → Curve25519`, `PLAIN`/other → unencrypted,
    `DIRECT` always Curve25519 — exactly the Python table.
  - `set_transport_encryption()` / `clear_transport_encryption_override()`
    for explicit overrides that survive re-determination.
- `reticulum-actor`: `Action::SendLxmfMessage` gained
  `transport_encryption: Option<String>` (`LxmfTransportEncryption` names).
- `reticulum-ffi`: mirrored in `AppAction::SendLxmfMessage`; bindings
  regenerated.
- Tests: `lxmf/src/message.rs::transport_encryption_tests` (9 tests),
  `reticulum-actor/tests/integration.rs` sends with the field set.

## 3. RNode link-quality telemetry ✅

- `src/iface.rs`
  - `InterfaceCounters::set_radio_quality(rssi, snr, quality)` plus
    `rssi()/snr()/quality()` getters; `InterfaceStats` carries
    `rssi: Option<i16>`, `snr: Option<f32>`, `quality: Option<f32>`.
- `src/iface/rnode.rs` — the KISS status parser publishes telemetry into
  the interface counters (single-radio and multi-radio workers).
- `src/transport.rs` — `interface_stats_for_link(link_id)` resolves the
  link's interface (inbound receiving interface via `in_link_ifaces`,
  intermediary link table, or the outbound path's next hop).
- `reticulum-actor` — `InterfaceSummary` and `CallSummary` expose
  `rssi`/`snr`/`quality`; `CallSummary::quality` blends audio-bridge
  delivery with radio `q` when both exist.
- Tests: `src/iface.rs` counter tests,
  `tests/resource_transfer.rs::interface_stats_for_link_resolves_the_links_interface`.

## 4. Shared-instance access configuration ✅

- `src/iface/local.rs`
  - `SharedInstanceAccessConfig { allow, required_token, max_clients }`
    with an HDLC-framed authentication handshake
    (`RNSLIA1 || name || token`, constant-time token compare).
  - `LocalServer::new_with_access`, `LocalClient::new_authenticated`,
    accepted clients keep their declared name in interface stats.
- `reticulum-actor`: `SharedInstanceAccessConfig` +
  `Action::StartSharedInstance { access }` and
  `Action::ConnectSharedInstance { access_token }`.
- `reticulum-ffi`: `AppSharedInstanceAccessConfig` + conversions; bindings
  regenerated.
- Tests: `tests/local_iface.rs` (token accepted/rejected, allow list,
  client cap), `reticulum-actor/tests/integration.rs`
  (`shared_instance_hosting_and_connecting`).

## 5. Audio pump performance / fallback ✅

- `reticulum-actor`
  - `AudioPolicy { warning_latency_ms, max_consecutive_failures,
    min_quality, quality_grace_ticks }` via `Action::SetAudioPolicy`.
  - The pump measures per-call `read_frames` latency, emits
    `Update::AudioWarning` on threshold breaches, and degrades to a
    null-codec fallback (the platform bridge is no longer called) after
    sustained failures.
  - `min_quality` auto-closes calls that stay below the floor for
    `quality_grace_ticks` network ticks.
- `reticulum-ffi`: `AppAudioPolicy`, `AppUpdate::AudioWarning`; bindings
  regenerated.
- Tests: `reticulum-actor/tests/integration.rs`
  (`audio_pump_warns_on_slow_bridge_callbacks_and_degrades`,
  `audio_policy_rejects_invalid_bounds`,
  `lxst_call_setup_and_teardown`).

## 6. Actor acceptance tests ✅

`reticulum-actor/tests/integration.rs` covers: TCP request/response
loopback, `TransportBridge` with a mock bridge, LXMF send/receipt between
two actors, propagation-node sync set/request/cancel, LXST call
setup/teardown with a mock `AudioBridge`, resource offer/accept/cancel,
discovery announce/listen/connect, shared-instance hosting with access
control, `LogBridge` fan-out verification, and the audio policy paths.

Fixed on the way (all now under test):

- Async request handlers no longer hold the transport handler lock while
  awaiting user code (this deadlocked the actor's state snapshots);
  `tests/async_request.rs` pins both immediate and deferred handlers.
- Actor `SendResponse` responses are msgpack-wrapped (Python parity).
- `AdvertiseResource` resolves outbound links by id through the tracked
  link table.
- Identities can be imported/created before the node starts.
- Propagation nodes announce when enabled
  (`Action::AnnounceLxmfPropagationNode`); call endpoints re-announce via
  `Action::AnnounceCallEndpoint`.
- Discovery announces fire on the first poll after registration instead
  of after the full poll interval.

## 7. FFI / mobile coverage ✅

- `reticulum-ffi/tests/ffi_callbacks.rs`: an `AppReconciler` implemented
  in Rust receives updates through `listen_for_updates`;
  `stop_listening` halts delivery and a restarted listener resumes;
  dispatching across the whole `AppAction` surface produces the
  documented updates; `FfiApp` restart after `Stop` works.
- `reticulum-ffi/tests/ffi_app.rs` (pre-existing) covers the lifecycle.

## 8. Benchmarks / CI ✅

- `reticulum-actor/benches/actor.rs` (criterion): dispatch throughput,
  state snapshot, audio bridge read/write latency.
- `reticulum-actor/tests/perf_floor.rs`: machine-stable absolute floors
  (dispatch ≥ 10k ops/s, audio callback round-trip < 1 ms) that fail CI
  on order-of-magnitude regressions.
- `.github/workflows/ci.yml`: a `benchmarks` job runs the floors in
  release mode (fails on regression) and the criterion benches.
- `Makefile`: `make mobile-smoke` builds the FFI library across the
  mobile feature matrix (host, cargo-ndk Android targets, Apple targets;
  missing toolchains are skipped with a warning).
