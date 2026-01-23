# GitHub Issue: Add Debug Logging for Packet Flow Diagnostics

**Repository:** `doubleailes/Reticulum-rs`  
**Type:** Enhancement  
**Priority:** Medium  
**Related:** PR #37

---

## Title

Add trace-level logging for packet flow between interface and transport handler

## Summary

After applying PR #37 (`filter_duplicate_packets` fix for Resource packets), Resource transfers still fail. The packets are received by `tcp_client` but never reach the transport handler's routing logic. There's a gap in logging between interface receive and transport processing, making it difficult to diagnose where packets are being lost.

## Problem

Current logging shows:

```
[DEBUG] tcp_client: rx << context=Resource dest=/xxx/ type=Data  ← Received ✓
# ... silence ...
[DEBUG] tcp_client: rx << context=KeepAlive ...                  ← Next packet
```

Missing logs that should appear:

```
[DEBUG] tp: routing packet type=Data ctx=Resource to handler     ← Never logged!
```

There's no visibility into:

1. Whether `rx_channel.send()` succeeds in tcp_client
2. Whether `rx_receiver.recv()` receives the packet in transport
3. Whether `filter_duplicate_packets()` is even called
4. What decision `filter_duplicate_packets()` makes

## Proposed Changes

### 1. `src/iface/tcp_client.rs` - Log channel send result

```rust
// Current:
let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;

// Proposed:
match rx_channel.send(RxMessage { address: iface_address, packet }).await {
    Ok(_) => log::trace!(
        "tcp_client: rx_channel.send() OK - ctx={:?}, dest={}",
        packet.context, packet.destination
    ),
    Err(e) => log::error!(
        "tcp_client: rx_channel.send() FAILED - ctx={:?}, dest={}, err={:?}",
        packet.context, packet.destination, e
    ),
}
```

### 2. `src/transport.rs` - Log packet receive

```rust
Some(message) = rx_receiver.recv() => {
    // Add at start:
    log::trace!(
        "tp: rx_receiver.recv() - ctx={:?}, dest={}, type={:?}",
        message.packet.context,
        message.packet.destination,
        message.packet.header.packet_type
    );
    // ... existing code ...
}
```

### 3. `src/transport.rs` - Log filter decision

```rust
async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
    // Add at function entry:
    log::trace!(
        "filter_duplicate_packets: ctx={:?}, dest={}, dest_type={:?}",
        packet.context, packet.destination, packet.header.destination_type
    );

    // At each early return, log the reason:
    if packet.header.destination_type == DestinationType::Link {
        log::trace!("filter_duplicate_packets: ALLOW (Link destination)");
        return true;
    }

    if matches!(packet.context, PacketContext::Resource | ...) {
        log::trace!("filter_duplicate_packets: ALLOW (Resource context)");
        return true;
    }
    // ... etc
}
```

## Expected Outcome

With these changes, the full packet flow will be visible:

```
[TRACE] tcp_client: rx << context=Resource dest=/xxx/ type=Data
[TRACE] tcp_client: rx_channel.send() OK - ctx=Resource, dest=/xxx/
[TRACE] tp: rx_receiver.recv() - ctx=Resource, dest=/xxx/, type=Data
[TRACE] filter_duplicate_packets: ctx=Resource, dest=/xxx/, dest_type=Link
[TRACE] filter_duplicate_packets: ALLOW (Link destination)
[DEBUG] tp: routing packet type=Data ctx=Resource to handler
```

Or, if there's a problem:

```
[TRACE] tcp_client: rx << context=Resource dest=/xxx/ type=Data
[TRACE] tcp_client: rx_channel.send() OK - ctx=Resource, dest=/xxx/
# No further logs = packet lost between channel send and receive
```

## Rationale

- All logging is at `trace` level, so it won't affect normal operation
- Helps diagnose packet flow issues without code changes
- Essential for debugging Resource transfer failures
- Follows existing logging patterns in the codebase

## Use Case

Debugging LXMF-rs message delivery:

1. Python LXMF sender sends message via Resource transfer
2. Rust receiver accepts ResourceAdvertisement, sends ResourceRequest
3. Resource data packets arrive at tcp_client
4. **Packets disappear** - no routing, no delivery, sender times out

This logging would immediately reveal where in the pipeline packets are lost.

## Acceptance Criteria

- [ ] `rx_channel.send()` logs success/failure
- [ ] `rx_receiver.recv()` logs received packets
- [ ] `filter_duplicate_packets()` logs entry and decision
- [ ] All new logging at `trace` level
- [ ] Resource transfer packets visible in trace output
