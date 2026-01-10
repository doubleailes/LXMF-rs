# GitHub Issue: Resource Data Packets Filtered as Duplicates

**Repository:** `doubleailes/Reticulum-rs`  
**Type:** Bug  
**Priority:** High  
**Affects:** Resource-based message delivery (LXMF large messages)
**Status:** ⚠️ PARTIALLY FIXED - See PR #37, but issue persists

---

## Title

`filter_duplicate_packets()` incorrectly filters Resource data packets, breaking Resource transfers

## Summary

The `filter_duplicate_packets()` function in `src/transport.rs` filters out `PacketContext::Resource` packets as duplicates, preventing the `ResourceManager` from receiving data parts and completing resource transfers. This breaks LXMF message delivery for messages sent via the Resource protocol.

## Update (2026-01-10): PR #37 Applied But Issue Persists

PR #37 (`copilot/fix-filter-duplicate-packets-again` @ `4b6c231a`) was merged with the fix to allow Resource packets through `filter_duplicate_packets()`. However, testing shows Resource packets are **still not being routed** to the handler.

### Evidence After Fix

```
[21:50:24Z] tcp_client: rx << context=Resource dest=/0dc17ce77df425fb2ef09d4e5d9ab234/ type=Data
[21:50:24Z] tcp_client: rx << context=Resource dest=/0dc17ce77df425fb2ef09d4e5d9ab234/ type=Data
# ^^^ Resource packets received by tcp_client
# NO "routing packet type=Data ctx=Resource to handler" log!
# NO "dropping duplicate packet" log either!
[21:50:29Z] tcp_client: rx << context=KeepAlive ...
```

The packets are:
1. ✅ Received by tcp_client (logged at "rx <<")
2. ❌ NOT dropped by filter (no "dropping duplicate" log)
3. ❌ NOT routed to handler (no "routing packet" log)

This suggests the issue is **not in `filter_duplicate_packets()`** but somewhere else in the packet processing pipeline between tcp_client receiving the packet and transport routing it.

## Current Behavior

When a Resource transfer is initiated:

1. `ResourceAdvertisement` packet is received ✅
2. `ResourceRequest` is sent back ✅  
3. `Resource` data packets are received by the TCP interface ✅
4. **Resource data packets are filtered out by `filter_duplicate_packets()`** ❌
5. `ResourceManager` never receives the data parts
6. Resource transfer never completes
7. No `ResourceProof` (delivery receipt) is sent
8. Sender times out and retries

## Expected Behavior

Resource data packets (`PacketContext::Resource`) should pass through `filter_duplicate_packets()` and be delivered to the `ResourceManager` for processing, allowing resource transfers to complete successfully.

## Root Cause

In `src/transport.rs` around lines 1000-1033, the `filter_duplicate_packets()` function only allows specific packet types through:

```rust
match packet.header.packet_type {
    PacketType::Announce => return true,      // Allowed ✓
    PacketType::LinkRequest => return true,   // Allowed ✓
    // NO handling for Resource packets!      // Filtered ✗
}
```

Packets with `PacketContext::Resource` are not given special handling, causing them to be filtered as duplicates.

## Evidence from Logs

```
[DEBUG reticulum::iface::tcp_client] tcp_client: rx << context=ResourceAdvrtisement dest=/3493352f.../ type=Data
[DEBUG LXMF_rs::router::router] Processing resource packet: type=Data, context=ResourceAdvrtisement
[INFO  reticulum::resource] ResourceRequest: sending packet - dest=/3493352f.../ context=ResourceRequest
[DEBUG reticulum::iface::tcp_client] tcp_client: rx << context=Resource dest=/3493352f.../ type=Data
[DEBUG reticulum::iface::tcp_client] tcp_client: rx << context=Resource dest=/3493352f.../ type=Data
# ^^^ Resource packets received but never processed - no further Resource events
[DEBUG reticulum::iface::tcp_client] tcp_client: rx << context=KeepAlive ...
[DEBUG reticulum::iface::tcp_client] tcp_client: rx << context=LinkClose ...
# ^^^ Link closes without resource completion, sender retries
```

## Proposed Fix

Add handling for `PacketContext::Resource` in `filter_duplicate_packets()`:

```rust
// In filter_duplicate_packets(), for PacketType::Data:
PacketType::Data => {
    // Resource data packets should not be filtered as duplicates
    // They are sequential parts of a resource transfer
    if packet.context == PacketContext::Resource {
        return true;
    }
    // ... existing duplicate filtering logic for other Data packets
}
```

Alternatively, check the context before the packet type match:

```rust
fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
    // Resource packets should always pass through - they are sequential transfer parts
    if packet.context == PacketContext::Resource 
        || packet.context == PacketContext::ResourceAdvertisement
        || packet.context == PacketContext::ResourceRequest {
        return true;
    }
    
    // ... rest of existing logic
}
```

## Impact

- **LXMF-rs:** Cannot receive messages via Resource-based delivery (used for larger messages)
- **Delivery receipts:** Python sender never receives acknowledgment, retries 4 times, then fails
- **Interoperability:** Rust receiver cannot fully interoperate with Python LXMF sender

## Test Case

1. Start Rust receiver with LXMF-rs
2. Send LXMF message from Python sender (message will use Resource transfer)
3. Observe that ResourceAdvertisement is received and ResourceRequest is sent
4. Observe that Resource data packets are logged by tcp_client but never processed
5. Sender times out and retries

## Related

- Python RNS `resource.py` - Reference implementation
- LXMF-rs branch: `copilot/add-receiver-example`
- Reticulum-rs branch: `copilot/fix-filter-duplicate-packets`

## Environment

- Reticulum-rs commit: `269a8b72` (branch `copilot/fix-filter-duplicate-packets`)
- LXMF-rs: branch `copilot/add-receiver-example`
- Python RNS/LXMF: Latest release
- Connection: TCP client to `127.0.0.1:4242`

---

## Checklist for Fix

- [x] Add `PacketContext::Resource` handling in `filter_duplicate_packets()` (PR #37)
- [x] Ensure `ResourceAdvertisement` and `ResourceRequest` also pass through (PR #37)
- [x] Add test for Resource packet filtering behavior (PR #37)
- [ ] **NEW**: Investigate why Resource packets don't reach transport routing after PR #37
- [ ] Verify end-to-end Resource transfer completes
- [ ] Verify `ResourceProof` is sent on completion
- [ ] Test with Python LXMF sender → Rust receiver

---

## Important Note: Previous "Success" Was NOT Resource Transfer

The successful LXMF message reception at 21:11 UTC was via **direct link packet** (`context=None`, 308 bytes), NOT via Resource transfer. The message was small enough to fit in a single link packet.

```
# PREVIOUS SUCCESS (21:11 UTC) - Direct Link Packet
[21:11:01Z] tcp_client: rx << context=None type=Data    ← context=None!
[21:11:01Z] tp: routing packet type=Data ctx=None       ← Routed ✓
[21:11:01Z] link: data 308B
[21:11:01Z] Received link event: event_type="Data"      ← Delivered ✓

# CURRENT FAILURE (21:50 UTC) - Resource Transfer
[21:50:24Z] tcp_client: rx << context=Resource type=Data  ← context=Resource
# NO routing log                                          ← NOT Routed ✗
```

**Resource transfer has never successfully completed in Rust.**
