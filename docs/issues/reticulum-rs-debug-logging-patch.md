# Debug Logging Patch for Reticulum-rs

This patch adds debug logging between `rx_channel.send()` in tcp_client and `rx_receiver.recv()` in transport to diagnose why Resource packets are not being routed.

## Instructions

1. Apply these changes to your local Reticulum-rs clone
2. Update LXMF-rs Cargo.toml to use local path:

   ```toml
   [dependencies.reticulum]
   path = "../Reticulum-rs"
   ```

3. Rebuild and test

---

## File: `src/iface/tcp_client.rs`

### Change 1: Add logging after successful channel send (around line 155)

Find this code:

```rust
let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
```

Replace with:

```rust
match rx_channel.send(RxMessage { address: iface_address, packet }).await {
    Ok(_) => {
        log::trace!(
            "tcp_client: rx_channel.send() SUCCESS - ctx={:?}, dest={}, type={:?}",
            packet.context,
            packet.destination,
            packet.header.packet_type
        );
    }
    Err(e) => {
        log::error!(
            "tcp_client: rx_channel.send() FAILED - ctx={:?}, dest={}, error={:?}",
            packet.context,
            packet.destination,
            e
        );
    }
}
```

---

## File: `src/transport.rs`

### Change 2: Add logging at start of packet receive loop (around line 1730)

Find this code in `manage_transport()`:

```rust
Some(message) = rx_receiver.recv() => {
    let _ = iface_messages_tx.send(message);

    let packet = message.packet;

    let handler = handler.lock().await;

    if PACKET_TRACE {
```

Replace with:

```rust
Some(message) = rx_receiver.recv() => {
    log::trace!(
        "tp: rx_receiver.recv() - ctx={:?}, dest={}, type={:?}",
        message.packet.context,
        message.packet.destination,
        message.packet.header.packet_type
    );

    let _ = iface_messages_tx.send(message);

    let packet = message.packet;

    let handler = handler.lock().await;

    log::trace!(
        "tp: acquired handler lock - ctx={:?}, dest={}, type={:?}",
        packet.context,
        packet.destination,
        packet.header.packet_type
    );

    if PACKET_TRACE {
```

### Change 3: Add logging after filter check (around line 1745)

Find this code:

```rust
if !handler.filter_duplicate_packets(&packet).await {
    log::debug!(
        "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
        handler.config.name,
        packet.destination,
        packet.context,
        packet.header.packet_type
    );
    continue;
}
```

Add BEFORE this block:

```rust
log::trace!(
    "tp: about to call filter_duplicate_packets - ctx={:?}, dest={}, type={:?}",
    packet.context,
    packet.destination,
    packet.header.packet_type
);
```

And add AFTER the if block (before the routing log):

```rust
log::trace!(
    "tp: filter_duplicate_packets returned true (packet allowed) - ctx={:?}, dest={}",
    packet.context,
    packet.destination
);
```

---

## File: `src/transport.rs` - filter_duplicate_packets function

### Change 4: Add logging at start of filter function (around line 1010)

Find the start of `filter_duplicate_packets`:

```rust
async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
```

Add at the very beginning of the function:

```rust
async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
    log::trace!(
        "filter_duplicate_packets: ENTER - ctx={:?}, dest={}, dest_type={:?}, type={:?}",
        packet.context,
        packet.destination,
        packet.header.destination_type,
        packet.header.packet_type
    );
```

### Change 5: Add logging at Link destination early return

Find this code (should be near the start):

```rust
// Link-destined packets bypass filtering
if packet.header.destination_type == DestinationType::Link {
    return true;
}
```

Replace with:

```rust
// Link-destined packets bypass filtering
if packet.header.destination_type == DestinationType::Link {
    log::trace!(
        "filter_duplicate_packets: BYPASS (DestinationType::Link) - ctx={:?}, dest={}",
        packet.context,
        packet.destination
    );
    return true;
}
```

### Change 6: Add logging at Resource context early return

Find this code:

```rust
// Resource packets bypass filtering - sequential transfer parts
if matches!(
    packet.context,
    PacketContext::Resource
        | PacketContext::ResourceAdvrtisement
        | PacketContext::ResourceRequest
        | PacketContext::ResourceHashUpdate
        | PacketContext::ResourceProof
        | PacketContext::ResourceInitiatorCancel
        | PacketContext::ResourceReceiverCancel
) {
    return true;
}
```

Replace with:

```rust
// Resource packets bypass filtering - sequential transfer parts
if matches!(
    packet.context,
    PacketContext::Resource
        | PacketContext::ResourceAdvrtisement
        | PacketContext::ResourceRequest
        | PacketContext::ResourceHashUpdate
        | PacketContext::ResourceProof
        | PacketContext::ResourceInitiatorCancel
        | PacketContext::ResourceReceiverCancel
) {
    log::trace!(
        "filter_duplicate_packets: BYPASS (Resource context) - ctx={:?}, dest={}",
        packet.context,
        packet.destination
    );
    return true;
}
```

---

## Expected Output With Patch

If packets flow correctly, you should see:

```
[TRACE] tcp_client: rx_channel.send() SUCCESS - ctx=Resource, dest=/xxx/, type=Data
[TRACE] tp: rx_receiver.recv() - ctx=Resource, dest=/xxx/, type=Data
[TRACE] tp: acquired handler lock - ctx=Resource, dest=/xxx/, type=Data
[TRACE] tp: about to call filter_duplicate_packets - ctx=Resource, dest=/xxx/, type=Data
[TRACE] filter_duplicate_packets: ENTER - ctx=Resource, dest=/xxx/, ...
[TRACE] filter_duplicate_packets: BYPASS (DestinationType::Link) - ctx=Resource, dest=/xxx/
[TRACE] tp: filter_duplicate_packets returned true - ctx=Resource, dest=/xxx/
[DEBUG] tp: routing packet type=Data ctx=Resource to handler
```

If packets are being lost, you'll see where the chain breaks.

---

## Hypothesis

Based on current logs, my hypothesis is:

1. `tcp_client: rx << context=Resource` - Packet received ✓
2. `rx_channel.send()` - Might be blocking or failing silently
3. `rx_receiver.recv()` - Never receives the packet

The issue might be **channel capacity** or **async runtime scheduling**.
