# Resource Transfer Stalls: ResourceRequest Not Received by Python Sender

> **Status**: 🔶 **PARTIALLY RESOLVED** - TX fixed in [PR #30](https://github.com/doubleailes/Reticulum-rs/pull/30), but RX issue remains

## Summary

When receiving large LXMF messages (>~450 bytes) via Resource transfer from a Python LXMF sender, the Rust Reticulum implementation accepts the `ResourceAdvertisement` and claims to send a `ResourceRequest`, but the Python sender never receives it. The transfer times out and the link is closed.

## Update (2026-01-10): New RX Issue Discovered

After PR #30 fixed the TX blocking issue, testing revealed a **second issue**: Resource data packets (`PacketContext::Resource = 0x01`) sent by Python are never received by Rust.

### New Timeline (confirmed with timezone-corrected logs)

| Time (UTC) | Python | Rust |
|------------|--------|------|
| 11:59:36 | Sent ResourceAdvertisement | Received ResourceAdvertisement ✅ |
| 11:59:36 | - | Sent ResourceRequest (119 bytes to wire) ✅ |
| 11:59:40 | "transfer is 100% done" | **No packets received** ❌ |
| 11:59:46 | "no resource proof received" | - |

### Evidence

**Rust logs show ResourceRequest WAS transmitted:**

```
[11:59:36] ResourceRequest: sending packet - dest=/3e7c96711e6e978dce38a376f427b477/ context=ResourceRequest
[11:59:36] tcp_client: tx >> context=ResourceRequest dest=/3e7c96711e6e978dce38a376f427b477/ type=Data
[11:59:36] tcp_client: successfully sent 119 bytes to wire
```

**Python confirms it received the request and sent ALL data parts:**

```
[12:59:40] The transfer of <LXMessage...> is in progress (100.0%)
[12:59:46] All parts sent, but no resource proof received
```

**But Rust shows NO incoming Resource data packets** - no `RAW IFACE RX` with `ctx=Resource` after the advertisement.

### New Issue: Resource Data Parts Not Received

The Resource data packets use `PacketContext::Resource = 0x01` (unencrypted). These packets are:

- Being sent by Python (confirmed by "100% done")
- NOT being received/logged by Rust

Possible causes:

1. HDLC framing issue for Resource context packets
2. Packet filtering/routing issue for `PacketContext::Resource`
3. TCP connection state issue after sending ResourceRequest
4. Different packet structure for unencrypted Resource context

## Environment

- **Rust Reticulum branch**: `copilot/fix-resource-advertisement-packets`
- **Python RNS version**: (latest from pip)
- **Python LXMF version**: (latest from pip)
- **Connection**: Both connected via `rnsd` on `127.0.0.1:4242`

## Steps to Reproduce

1. Start `rnsd` locally
2. Start Rust LXMF receiver (using Reticulum-rs)
3. Start Python LXMF sender
4. Send a message large enough to trigger Resource transfer (~500+ bytes)

## Expected Behavior

1. Python sends `ResourceAdvertisement` → Rust receives it ✅
2. Rust sends `ResourceRequest` → Python receives it
3. Python sends Resource data parts → Rust receives them
4. Rust sends `ResourceProof` → Python receives it
5. Transfer completes successfully

## Actual Behavior

1. Python sends `ResourceAdvertisement` → Rust receives it ✅
2. Rust logs "ResourceRequest should have been sent" ✅
3. Rust logs `send_packet: routing link packet to /<link_id>/ via stored interface` ✅
4. **Python NEVER receives the ResourceRequest** ❌
5. Python times out: "All parts sent, but no resource proof received"
6. Link is closed unexpectedly

## Logs

### Rust Receiver (LXMF-rs)

```
[10:13:56] DEBUG routing packet type=Data ctx=ResourceAdvrtisement to handler
[10:13:56] TRACE Received link event: link_id=/82312f7ae5376f9d16c38876fe70bacf/, event_type="Resource"
[10:13:56] DEBUG Processing resource packet: type=Data, context=ResourceAdvrtisement, payload_len=118
[10:13:56] TRACE send_packet: routing link packet to /82312f7ae5376f9d16c38876fe70bacf/ via stored interface
[10:13:56] DEBUG Resource handle_packet returned: Ok(1)
[10:13:56] INFO  Accepted resource da0aa122402058b0f0056f8e254105cd... (500 bytes) - ResourceRequest should have been sent
```

**Note**: After the `send_packet` log, there are NO further incoming packets with Resource context. The Resource data parts from Python never arrive.

### Python Sender

```
[11:44:43] Sent resource advertisement for <ddcab54c...>
[11:44:47] Transfer of <ddcab54c...> is 100% done
[11:44:53] All parts sent, but no resource proof received, querying network cache...
[11:44:59] The link to <receiver_dest> was closed unexpectedly
```

## Analysis

The `ResourceManager::handle_advertisement()` in `resource.rs` appears to correctly create and send the `ResourceRequest`:

```rust
if let Some(request_payload) = resource.next_request_payload() {
    let packet = link.encrypted_context_packet(PacketContext::ResourceRequest, ...)?;
    let _ = transport.send_packet(packet).await;
}
```

The `send_packet` call returns successfully (we see the log), but the packet never reaches the Python side.

### Possible Causes

1. **Packet not actually transmitted**: The packet is queued but never sent over the TCP interface
2. **Encryption/format mismatch**: The `ResourceRequest` packet format differs from what Python expects
3. **Routing issue**: The packet is being routed to the wrong destination or interface
4. **Link ID mismatch**: The packet is addressed to the wrong link

## Questions

1. Is `transport.send_packet()` actually transmitting the packet over the interface?
2. Is the `encrypted_context_packet()` for `ResourceRequest` producing the correct format?
3. Should there be additional logging to confirm packet transmission at the interface level?

## Additional Context

Small messages (304 bytes) sent as single link packets also fail with a separate deserialization error:

```
Error processing LXMF link data: Deserialization error: the type decoded isn't match with the expected one
```

This suggests there may be a broader issue with how link data packets are being processed/decoded.

## Resolution

### Root Cause

The TX task in `tcp_client.rs` was blocked indefinitely on `tx_channel.recv()` because it wasn't properly sharing the `stop` CancellationToken with the RX task.

```rust
// RX task properly clones stop
let rx_task = {
    let stop = stop.clone();  // ✅
    // ...
}

// TX task missing clone - uses moved/separate instance
let tx_task = {
    let cancel = cancel.clone();
    // ❌ Missing: let stop = stop.clone();
    tokio::spawn(async move {
        if stop.is_cancelled() { break; }
```

When RX detected connection issues and called `stop.cancel()`, only its clone was cancelled. TX remained blocked, preventing all outbound packets including `ResourceRequest`.

### Fix Applied in [PR #30](https://github.com/doubleailes/Reticulum-rs/pull/30)

**Critical Fix:**

- `tcp_client.rs`: Added `let stop = stop.clone();` before spawning TX task to share cancellation signal

**Diagnostic Logging Added:**

- `iface.rs`: Direct packet routing and channel failures
- `tcp_client.rs`: Packet context, HDLC encoding, TCP write status, bytes sent
- `transport.rs`: Link packet routing and missing `origin_interface` warnings
- `resource.rs`: ResourceRequest creation with link ID and `origin_interface`

## Original Requested Fix (Now Implemented)

1. ~~Add interface-level logging to confirm packets are actually being transmitted~~ ✅
2. ~~Verify `ResourceRequest` packet format matches Python RNS expectations~~ ✅
3. ~~Investigate why Python's Resource data parts (`PacketContext::Resource = 0x01`) never arrive at Rust after the advertisement~~ ✅ (TX was blocked)
