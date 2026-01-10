# Link Data Packets (Resource context) Dropped by Duplicate Filter

## Summary

After applying the TCP buffer fix from PR #33, Resource data packets (`PacketContext::Resource = 0x01`) now **arrive at the TCP client** but are being **dropped by `filter_duplicate_packets()`** in the transport layer. The packets never reach `handle_data()` or trigger `LinkEvent::Resource`.

## Environment

- **Rust Reticulum branch**: `main` (with PR #33 merged)
- **Python RNS version**: latest from pip
- **Python LXMF version**: latest from pip
- **Connection**: Both connected via `rnsd` on `127.0.0.1:4242`
- **Rust version**: 1.92.0

## Progress from PR #33

The TCP buffer fix is **working** - we now see Resource data packets being received at the TCP layer:

```
tcp_client: read 576 bytes from TCP stream
tcp_client: rx << context=Resource dest=/4fc13484302e17b0379123e59d5bf52a/ type=Data
tcp_client: rx << context=Resource dest=/4fc13484302e17b0379123e59d5bf52a/ type=Data
```

**Before PR #33**: These packets never appeared at all.
**After PR #33**: TCP layer receives them ✅

## The New Problem

The packets arrive at `tcp_client` but are **dropped before transport routing**:

| Packet Type | tcp_client rx | transport routing | Result |
|-------------|---------------|-------------------|--------|
| ResourceAdvertisement | ✅ `rx <<` | ✅ `routing packet` | Works |
| Resource (data) | ✅ `rx <<` | ❌ No log | **Dropped** |

### Log Evidence

```
# ResourceAdvertisement - WORKS
tcp_client: rx << context=ResourceAdvrtisement dest=/4fc13484.../ type=Data
tp(tp): routing packet type=Data ctx=ResourceAdvrtisement to handler  ✅

# Resource data - DROPPED
tcp_client: rx << context=Resource dest=/4fc13484.../ type=Data
(nothing - no "routing packet" log)  ❌
```

## Root Cause

### Location
`src/transport.rs` lines 1006-1033 in `filter_duplicate_packets()`:

```rust
async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
    let mut allow_duplicate = false;

    match packet.header.packet_type {
        PacketType::Announce => {
            return true;  // ✅ Allowed through
        }
        PacketType::LinkRequest => {
            return true;  // ✅ Allowed through (added in LINK_REQUEST_FIX)
        }
        PacketType::Proof => {
            if packet.context == PacketContext::LinkRequestProof {
                // Special handling...
            }
        }
        _ => {}  // ❌ Data packets fall through here
    }

    let is_new = self.packet_cache.lock().await.update(packet);

    is_new || allow_duplicate  // Returns false if packet hash already in cache
}
```

### The Bug

Link-destined packets with `DestinationType::Link` are treated the same as global broadcast packets:
1. Resource data packets have `PacketType::Data` and `DestinationType::Link`
2. They fall through to the `packet_cache.update()` check
3. If multiple Resource packets are sent (which is normal for any file transfer), subsequent packets may have the same hash if they're retry packets OR get caught in the cache timing
4. **Critical**: Even legitimate non-duplicate Resource packets are being filtered

### Why This Affects Link Packets Specifically

Link packets are **point-to-point** and should not be subject to global duplicate filtering:
- Link ID serves as the "session" identifier
- Each Resource data part has different content but may arrive rapidly
- The Link layer (`handle_data_packet()`) handles its own state management
- Python RNS does NOT apply duplicate filtering to Link-destined packets

## Packet Flow (What Should Happen)

```
TCP Socket → HDLC Decode → Interface → Transport → handle_data() → Link.handle_packet()
                                         ↑
                               filter_duplicate_packets()
                               should ALLOW Link packets through
```

## Proposed Fix

Add `DestinationType::Link` to the bypass list in `filter_duplicate_packets()`:

```rust
async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
    // Link-destined packets should bypass duplicate filtering
    // They have their own session management via the Link
    if packet.header.destination_type == DestinationType::Link {
        return true;
    }

    let mut allow_duplicate = false;

    match packet.header.packet_type {
        PacketType::Announce => {
            return true;
        }
        PacketType::LinkRequest => {
            return true;
        }
        // ... rest unchanged
    }
    
    let is_new = self.packet_cache.lock().await.update(packet);
    is_new || allow_duplicate
}
```

### Alternative: Context-Based Bypass

If broader Link bypass is not desired, add specific Resource contexts:

```rust
match packet.context {
    PacketContext::Resource
    | PacketContext::ResourceAdvrtisement
    | PacketContext::ResourceRequest
    | PacketContext::ResourceHashUpdate
    | PacketContext::ResourceProof => {
        return true;  // Resource packets bypass duplicate filter
    }
    _ => {}
}
```

## Test Case

Add a unit test similar to `link_request_not_filtered_as_duplicate`:

```rust
#[tokio::test]
async fn link_data_packets_not_filtered_as_duplicate() {
    let transport = Transport::new(TransportConfig::default());
    let handler = transport.get_handler();

    let link_id = AddressHash::new_from_rand(OsRng);

    // Create a Link Data packet with Resource context
    let mut resource_packet: Packet = Default::default();
    resource_packet.header.packet_type = PacketType::Data;
    resource_packet.header.destination_type = DestinationType::Link;
    resource_packet.destination = link_id;
    resource_packet.context = PacketContext::Resource;
    resource_packet.data = PacketDataBuffer::new_from_slice(b"resource_data_part");

    // First packet should be allowed
    assert!(
        handler.lock().await.filter_duplicate_packets(&resource_packet).await,
        "First Resource packet should be allowed"
    );

    // Second identical packet should ALSO be allowed (Link packets bypass filter)
    assert!(
        handler.lock().await.filter_duplicate_packets(&resource_packet).await,
        "Duplicate Link packets should be allowed"
    );
}
```

## Full Log Evidence

### Rust Receiver (UTC)
```
[18:35:48] tcp_client: rx << context=ResourceAdvrtisement dest=/4fc13484.../ type=Data
[18:35:48] tp(tp): routing packet type=Data ctx=ResourceAdvrtisement to handler
[18:35:48] Processing resource packet: type=Data, context=ResourceAdvrtisement
[18:35:48] ResourceRequest: sending packet - dest=/4fc13484.../
[18:35:48] tcp_client: tx >> context=ResourceRequest
[18:35:48] tcp_client: successfully sent 118 bytes to wire
[18:35:48] Accepted resource ac8ae0d8... (474 bytes) - ResourceRequest sent

# HERE: Resource data packets arrive but are NOT routed
[18:35:48] tcp_client: read 576 bytes from TCP stream
[18:35:48] tcp_client: rx << context=Resource dest=/4fc13484.../ type=Data
[18:35:48] tcp_client: rx << context=Resource dest=/4fc13484.../ type=Data
# ❌ NO "tp(tp): routing packet" logs for Resource context

[18:35:53] tcp_client: rx << context=KeepAlive ...
[18:35:58] tcp_client: rx << context=KeepAlive ...
[18:36:03] tcp_client: rx << context=LinkClose ...
```

### Python Sender (CEST = UTC+2)
```
[19:35:48] Sent resource advertisement for <ac8ae0d8...>
[19:35:52] The transfer is in progress (100.0%)
[19:35:56] The transfer is in progress (100.0%)
[19:35:58] All parts sent, but no resource proof received, querying network cache...
[19:36:04] The link was closed unexpectedly
```

## Impact

- **Complete Resource transfer failure** when using LXMF or any file transfer
- Python sends all parts successfully (100%)
- Rust receives packets at TCP layer but drops them
- No `ResourceProof` is ever sent back
- Links timeout and close

## Related

- PR #33: Fixed TCP buffer issue (RX path) - **This is working now**
- PR #30: Fixed ResourceRequest TX issue - **This is working**
- `LINK_REQUEST_FIX.md`: Documents similar fix for LinkRequest packets
- `RESOURCE_PACKET_HANDLING.md`: Documents Link packet handling (works IF packets reach the handler)

## Files to Modify

- `src/transport.rs`: Add Link packet bypass in `filter_duplicate_packets()` (lines 1006-1033)

## Checklist

- [ ] Add `DestinationType::Link` bypass to `filter_duplicate_packets()`
- [ ] Add unit test `link_data_packets_not_filtered_as_duplicate`
- [ ] Verify Resource transfer completes successfully
- [ ] Update `LINK_REQUEST_FIX.md` or create similar documentation
