# Resource Data Packets Not Received After ResourceRequest Sent

## Summary

After sending a `ResourceRequest` to a Python RNS sender, the subsequent Resource data packets (`PacketContext::Resource = 0x01`) are never received by Rust. Python confirms it sent all parts (100% done), but Rust never sees them arrive at the interface.

## Environment

- **Rust Reticulum branch**: `copilot/fix-resource-request-issue` (includes TX fix from PR #30)
- **Python RNS version**: latest from pip
- **Python LXMF version**: latest from pip
- **Connection**: Both connected via `rnsd` on `127.0.0.1:4242`

## Related

- PR #30 fixed the TX blocking issue - ResourceRequest packets are now transmitted successfully
- This is a **separate RX issue** discovered after the TX fix

## Steps to Reproduce

1. Start `rnsd` locally
2. Start Rust LXMF receiver (using latest Reticulum-rs with PR #30 fix)
3. Start Python LXMF sender
4. Send a message large enough to trigger Resource transfer (~500+ bytes)

## Expected Behavior

1. Python sends `ResourceAdvertisement` → Rust receives it ✅
2. Rust sends `ResourceRequest` → Python receives it ✅ (PR #30 fixed this)
3. Python sends Resource data parts → Rust receives them
4. Rust sends `ResourceProof` → Python receives it
5. Transfer completes successfully

## Actual Behavior

1. Python sends `ResourceAdvertisement` → Rust receives it ✅
2. Rust sends `ResourceRequest` → Python receives it ✅
3. Python sends Resource data parts → **Rust NEVER receives them** ❌
4. Python times out: "All parts sent, but no resource proof received"
5. Link is closed

## Logs

### Timeline (UTC-adjusted)

| Time (UTC) | Python | Rust |
|------------|--------|------|
| 11:59:36 | Sent ResourceAdvertisement | Received ResourceAdvertisement ✅ |
| 11:59:36 | - | Sent ResourceRequest (119 bytes) ✅ |
| 11:59:40 | "transfer is 100% done" | **No packets received** ❌ |
| 11:59:46 | "no resource proof received" | - |

### Rust Receiver

```
[11:59:36] DEBUG routing packet type=Data ctx=ResourceAdvrtisement to handler
[11:59:36] INFO  RAW IFACE RX: dest=/3e7c96711e6e978dce38a376f427b477/, type=Data, ctx=ResourceAdvrtisement
[11:59:36] DEBUG Processing resource packet: type=Data, context=ResourceAdvrtisement, payload_len=118
[11:59:36] INFO  ResourceRequest: sending packet - dest=/3e7c96711e6e978dce38a376f427b477/ context=ResourceRequest
[11:59:36] DEBUG tcp_client: tx >> context=ResourceRequest dest=/3e7c96711e6e978dce38a376f427b477/ type=Data
[11:59:36] DEBUG tcp_client: successfully sent 119 bytes to wire
[11:59:36] INFO  Accepted resource 3b628882fa3c307daa77fb1ebf7e886340a06e9c92efd2c5d35fb438b6230a88 (478 bytes)

# ❌ NO FURTHER PACKETS RECEIVED - no ctx=Resource logs appear
```

### Python Sender

```
[12:59:36] Sent resource advertisement for <3b628882fa3c307daa77fb1ebf7e886340a06e9c92efd2c5d35fb438b6230a88>
[12:59:40] The transfer of <LXMessage 91f653a4b543f93ae0b4e4cb0dff135b01b6c673df4f168ff3083354e3f5ae2c> is in progress (100.0%)
[12:59:46] All parts sent, but no resource proof received, querying network cache...
[12:59:52] The link to <2c697c2b7f35db16e5a6605873044bca> was closed unexpectedly
```

## Analysis

### What's Working

1. ✅ TCP connection is alive (ResourceRequest was transmitted)
2. ✅ ResourceRequest packet format is correct (Python received it and responded)
3. ✅ Link is established and active

### What's Broken

Resource data packets use `PacketContext::Resource = 0x01`. These packets:

- Are being sent by Python (confirmed by "100% done")
- Are NOT arriving at Rust's `RAW IFACE RX` monitor
- Are NOT being routed to any handler

### Possible Causes

1. **HDLC framing issue**: Resource data packets may have different framing than other packets
2. **TCP RX task issue**: Similar to the TX issue fixed in PR #30, maybe the RX task has a problem
3. **Packet context filtering**: Resource context (`0x01`) may not be handled in the RX path
4. **Link packet routing**: Resource data packets may be routed differently than advertisements

### Key Observation

The `RAW IFACE RX` monitor logs ALL packets arriving at the interface. Since Resource data packets don't appear there, they're either:

- Not being received from the TCP socket
- Being received but dropped before the interface processes them
- Never being sent by Python (unlikely given "100% done" log)

## Requested Investigation

1. Add debug logging to `tcp_client.rs` RX path to log ALL incoming bytes/packets
2. Verify Resource data packets use the same HDLC framing as other packets
3. Check if there's any filtering in the RX path that drops `PacketContext::Resource`
4. Trace the packet from TCP socket → HDLC decode → interface → transport

## Packet Context Reference

```rust
pub enum PacketContext {
    None = 0x00,
    Resource = 0x01,           // ← Resource data parts use this
    ResourceAdvertisement = 0x02,  // ← Working
    ResourceRequest = 0x03,        // ← Working (TX fixed in PR #30)
    ResourceProof = 0x04,
    // ...
}
```

The issue is specifically with `PacketContext::Resource = 0x01` packets not being received.
