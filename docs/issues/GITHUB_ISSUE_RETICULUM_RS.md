# Resource Data Packets Not Reaching Link Event Handler

## Problem Summary

When receiving LXMF messages from a Python LXMF sender over a Reticulum link, the **Resource data packets** (`PacketContext::Resource = 0x01`) are logged at the TCP interface level but **never trigger `LinkEvent::Resource`** events. This causes Resource transfers to timeout after the initial handshake succeeds.

## Environment

- **Reticulum-rs**: `main` branch (commit as of 2026-01-10)
- **LXMF-rs**: Using Reticulum-rs as dependency
- **Python Sender**: Python LXMF 0.5.x with Python RNS
- **Interface**: TCP Client connecting to `amsterdam.connect.reticulum.network:4965`

## Observed Behavior

### What Works ✅
1. TCP connection establishes successfully
2. Announce packets are received and processed
3. Link establishment works (LinkRequest → LinkRequestProof → Link Activated)
4. `ResourceAdvertisement` packet is received and triggers `LinkEvent::Resource`
5. `ResourceRequest` packet is sent back to Python sender
6. Python sender confirms it sends all Resource data parts (100% progress)

### What Fails ❌
1. **Resource data packets** (`context=Resource`, `type=Data`) arrive at TCP interface
2. These packets are logged by `tcp_client: rx <<` 
3. **No `LinkEvent::Resource` is emitted** for these packets
4. No "Processing resource packet" log appears in LXMF router
5. Transfer times out after ~15 seconds
6. Python sender reports: "All parts sent, but no resource proof received"

## Log Evidence

### Rust Receiver Logs (abbreviated)
```
[timestamp] Incoming link activated for destination 4c4b9424dae6b7010aeb7c5dd0b4c687
[timestamp] Received link event: event_type="Resource"
[timestamp] Processing resource packet: type=Data, context=ResourceAdvrtisement
[timestamp] Accepted resource b8e5c6b850... - sending ResourceRequest

# TCP layer receives Resource data packets:
[timestamp] tcp_client: rx << context=Resource dest=<link_id> type=Data
[timestamp] tcp_client: rx << context=Resource dest=<link_id> type=Data

# But NO corresponding LinkEvent::Resource for these packets!
# No "Processing resource packet: type=Data, context=Resource" logs

[timestamp] Link closed (timeout)
```

### Python Sender Logs
```
[timestamp] Starting transfer of <LXMessage ...>
[timestamp] Sent resource advertisement
[timestamp] Resource request received, sending parts
[timestamp] Transfer progress: 100%
[timestamp] All parts sent, waiting for proof...
[timestamp] Resource transfer timed out - no proof received
```

## Analysis

### Packet Flow Diagram
```
Python LXMF Sender                    Rust LXMF Receiver
       |                                      |
       |-------- LinkRequest --------------->|  ✅
       |<------- LinkRequestProof -----------|  ✅
       |                                      |
       |-------- ResourceAdvertisement ----->|  ✅ LinkEvent::Resource emitted
       |<------- ResourceRequest ------------|  ✅
       |                                      |
       |-------- Resource (data part 1) ---->|  ❌ Received at TCP, no LinkEvent
       |-------- Resource (data part 2) ---->|  ❌ Received at TCP, no LinkEvent
       |                                      |
       |         ... timeout ...              |
       |<------- LinkClose ------------------|
```

### Suspected Causes

1. **Packet Duplicate Filtering**: In `transport.rs`, the `filter_duplicate_packets()` function allows `Announce` and `LinkRequest` packets through unconditionally, but `Data` packets (including Resource context) go through the packet cache. If Resource data packets are being incorrectly filtered as duplicates, they won't reach `handle_data()`.

2. **Link Lookup Failure**: In `handle_data()`, packets with `DestinationType::Link` are routed via:
   ```rust
   if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
       let mut link = link.lock().await;
       let result = link.handle_packet(packet);
   }
   ```
   If `packet.destination` (the LinkId) doesn't match the key in `in_links`, the packet is silently dropped.

3. **TCP Buffer Issue (potentially incomplete fix)**: The `RESOURCE_DATA_PACKETS_FIX.md` documents a buffer overflow bug that affected large packets. While the fix changed `rx_buffer[BUFFER_SIZE-1]` to `rx_buffer[rx_buffer.len()-1]`, the packets ARE being logged at TCP level, suggesting this specific fix is working but there may be a related issue.

## Reproduction Steps

1. Start a Python LXMF receiver:
   ```python
   # Using standard LXMF example receiver
   python lxmf_receiver.py
   ```

2. Note the receiver's destination hash

3. Start Rust LXMF sender targeting that destination:
   ```bash
   cargo run --example sender <destination_hash> direct
   ```

4. Observe that the message transfer times out

5. Alternatively, test with Python sender → Rust receiver (same result)

## Proposed Investigation

1. Add debug logging in `handle_data()` to trace why Link packets aren't being routed:
   ```rust
   if packet.header.destination_type == DestinationType::Link {
       log::debug!(
           "handle_data: Link packet - dest={}, in_links.contains={}",
           packet.destination,
           handler.in_links.contains_key(&packet.destination)
       );
   }
   ```

2. Verify that Resource data packets aren't being filtered as duplicates by adding logging in `filter_duplicate_packets()`:
   ```rust
   if packet.context == PacketContext::Resource {
       log::debug!(
           "filter_duplicate_packets: Resource packet - is_new={}, hash={}",
           is_new,
           packet.hash()
       );
   }
   ```

3. Consider allowing `PacketContext::Resource` packets through the duplicate filter, similar to `LinkRequest`:
   ```rust
   PacketType::Data => {
       if packet.context == PacketContext::Resource {
           return true; // Allow Resource data packets through
       }
   }
   ```

## Related Documentation

- `RESOURCE_DATA_PACKETS_FIX.md` - Documents the TCP buffer fix for large packets
- `RESOURCE_PACKET_HANDLING.md` - Documents the Link-level Resource packet handling
- `LINK_REQUEST_FIX.md` - Documents duplicate filtering bypass for LinkRequest

## Impact

This issue completely breaks Resource transfers (used for LXMF message delivery over links), making Rust LXMF receivers unable to receive messages from Python LXMF senders.

## Workaround

None known. Single-packet delivery might work for very small messages, but typical LXMF messages exceed the single packet size limit and require Resource transfers.
