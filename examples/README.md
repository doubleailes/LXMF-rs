# LXMF-rs Examples

This directory contains examples demonstrating how to use LXMF-rs for sending and receiving messages over Reticulum networks.

## Examples

### Sender (`sender.rs`)

Demonstrates how to send LXMF messages to a specific destination.

**Usage:**
```bash
cargo run --example sender <destination-hash> [method]
```

**Parameters:**
- `destination-hash`: 32-character hexadecimal destination hash of the recipient
- `method` (optional): Delivery method - `direct` (default) or `opportunistic`

**Example:**
```bash
# Send a direct message
cargo run --example sender 564f0ec8b6ff3cbbedb3b2bb6069f567 direct

# Send an opportunistic message
cargo run --example sender 564f0ec8b6ff3cbbedb3b2bb6069f567 opportunistic
```

**Features:**
- Creates a temporary LXMF identity
- Registers a delivery identity for replies
- Connects to the Reticulum network
- Waits for a path to the destination
- Automatically applies stamp costs from announces
- Sends a test message with title and content

### Receiver (`receiver.rs`)

Demonstrates how to receive LXMF messages and print delivery information.

**Usage:**
```bash
cargo run --example receiver
```

**Features:**
- Creates a persistent LXMF identity
- Registers a delivery identity with display name "Anonymous Peer"
- Configurable stamp cost (default: 8)
- Registers a delivery callback to handle incoming messages
- Connects to the Reticulum network
- Automatically processes incoming LXMF packets
- Interactive announce functionality (press Enter to announce)

**Output:**
The receiver prints detailed information about received messages:
```
+--- LXMF Delivery ---------------------------------------------
| Source hash            : <32-character hex>
| Destination hash       : <32-character hex>
| Transport Encryption   : Curve25519
| Timestamp              : <formatted timestamp>
| Title                  : <message title>
| Content                : <message content>
| Fields                 : <optional fields map>
| Message signature      : Validated
| Stamp                  : Validated
+---------------------------------------------------------------
```

## Running Both Examples Together

1. **Start the receiver in one terminal:**
   ```bash
   cargo run --example receiver
   ```
   
   The receiver will print its destination hash, e.g.:
   ```
   Ready to receive on: 564f0ec8b6ff3cbbedb3b2bb6069f567
   ```

2. **Send a message from another terminal:**
   ```bash
   cargo run --example sender 564f0ec8b6ff3cbbedb3b2bb6069f567
   ```

3. **Announce the receiver (optional):**
   In the receiver terminal, press Enter to announce the delivery destination. This broadcasts the receiver's presence and stamp cost to the network.

## Configuration

### Receiver Configuration

The receiver example can be configured by modifying constants at the top of `receiver.rs`:

```rust
const REQUIRED_STAMP_COST: u8 = 8;      // Stamp cost for incoming messages
const ENFORCE_STAMPS: bool = false;      // Whether to enforce stamp validation
```

### Network Configuration

Both examples connect to the public Reticulum network via:
```
amsterdam.connect.reticulum.network:4965
```

To use a different network or local Reticulum instance, modify the TCP client address in the examples.

## Implementation Notes

### Message Flow

1. **Sender:**
   - Creates LXMF router and registers identity
   - Attaches to Reticulum transport
   - Requests path to destination
   - Waits for announce to get stamp cost
   - Creates and sends LXMF message
   - Router automatically generates stamps if needed

2. **Receiver:**
   - Creates LXMF router and registers delivery identity
   - Registers delivery callback function
   - Attaches to Reticulum transport
   - Router automatically spawns background task to process incoming messages
   - When LXMF packet arrives:
     - Router unpacks the message
     - Validates signature
     - Triggers delivery callback

### Automatic Features

The LXMF router provides automatic handling for:

- **Stamp Cost Discovery:** Delivery announce handlers cache stamp costs from incoming announces
- **Stamp Generation:** Outbound messages automatically get stamps generated based on cached costs
- **Message Processing:** Incoming LXMF packets are automatically unpacked and routed to callbacks
- **Announce Handlers:** Both delivery and propagation announce handlers are registered automatically

## Python Compatibility

These examples are designed to be compatible with the Python LXMF implementation:
- Message format is byte-identical
- Stamp costs are encoded/decoded using the same msgpack format
- Announce data follows the Python LXMF 0.5.0+ format
- Signatures and encryption are compatible

You can send messages between Rust and Python LXMF implementations seamlessly.

## Troubleshooting

### "No path to destination"
- Ensure the destination is announcing (press Enter in receiver)
- Wait a few seconds for the announce to propagate
- Check network connectivity

### "Invalid signature"
- Message may have been tampered with
- Ensure sender and receiver are using compatible Reticulum identities

### "Stamp validation failed"
- Sender may not have the correct stamp cost
- Receiver may be enforcing stamps when ENFORCE_STAMPS=true

## References

- [Python LXMF Example Sender](https://github.com/markqvist/LXMF/blob/master/docs/example_minimal.py)
- [Python LXMF Example Receiver](https://github.com/markqvist/LXMF/blob/master/docs/example_receiver.py)
- [Reticulum Documentation](https://reticulum.network/manual/)
- [LXMF Specification](https://github.com/markqvist/LXMF)
