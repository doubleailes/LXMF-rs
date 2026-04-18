#!/usr/bin/env python3
"""
Python LXMF receiver for integration testing with LXMF-rs.

Starts a local Reticulum node with a TCP server, registers an LXMF delivery
identity, announces it, and waits for incoming messages. Prints received
messages as JSON to stdout for the test harness to parse.

Usage:
    python3 python_receiver.py [--port PORT] [--timeout SECS]

Output (one JSON object per line):
    {"event": "ready", "destination_hash": "...", "port": 12345}
    {"event": "message", "title": "...", "content": "...", "source": "...", "timestamp": ...}
    {"event": "timeout"}
"""

import argparse
import json
import os
import shutil
import signal
import sys
import tempfile
import time

import RNS
import LXMF


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=14965)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--display-name", default="Python LXMF Receiver")
    args = parser.parse_args()

    # Use a temp directory for Reticulum config so we don't interfere
    config_dir = tempfile.mkdtemp(prefix="lxmf_test_")

    # Write a minimal Reticulum config with a TCP server
    rns_config = f"""
[reticulum]
  enable_transport = false
  share_instance = false

[interfaces]
  [[TCP Server]]
    type = TCPServerInterface
    enabled = true
    listen_ip = 127.0.0.1
    listen_port = {args.port}
"""

    os.makedirs(os.path.join(config_dir, "reticulum"), exist_ok=True)
    with open(os.path.join(config_dir, "reticulum", "config"), "w") as f:
        f.write(rns_config)

    received_messages = []
    
    def message_callback(message):
        """Called when an LXMF message is received."""
        try:
            title = message.title.decode("utf-8") if message.title else ""
            content = message.content.decode("utf-8") if message.content else ""
            source_hash = RNS.prettyhexrep(message.source_hash) if message.source_hash else ""
            
            msg_data = {
                "event": "message",
                "title": title,
                "content": content,
                "source": source_hash,
                "timestamp": message.timestamp if hasattr(message, "timestamp") else 0,
                "method": str(message.method) if hasattr(message, "method") else "unknown",
            }
            print(json.dumps(msg_data), flush=True)
            received_messages.append(msg_data)
        except Exception as e:
            print(json.dumps({"event": "error", "error": str(e)}), flush=True)

    try:
        # Start Reticulum
        reticulum = RNS.Reticulum(
            configdir=os.path.join(config_dir, "reticulum"),
            loglevel=RNS.LOG_WARNING,
        )

        # Create identity and LXMF router
        identity = RNS.Identity()
        storage_path = os.path.join(config_dir, "lxmf_storage")
        os.makedirs(storage_path, exist_ok=True)
        
        router = LXMF.LXMRouter(
            identity=identity,
            storagepath=storage_path,
        )

        # Register delivery identity
        local_dest = router.register_delivery_identity(
            identity,
            display_name=args.display_name,
        )
        router.register_delivery_callback(message_callback)

        dest_hash = RNS.hexrep(local_dest.hash, delimit=False)

        # Announce
        router.announce(local_dest.hash)

        # Signal ready
        ready_msg = {
            "event": "ready",
            "destination_hash": dest_hash,
            "port": args.port,
            "identity_hash": RNS.hexrep(identity.hash, delimit=False),
        }
        print(json.dumps(ready_msg), flush=True)

        # Wait for messages or timeout
        deadline = time.time() + args.timeout

        def handle_signal(sig, frame):
            print(json.dumps({"event": "shutdown", "messages_received": len(received_messages)}), flush=True)
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        while time.time() < deadline:
            time.sleep(0.5)

        print(json.dumps({"event": "timeout", "messages_received": len(received_messages)}), flush=True)

    finally:
        shutil.rmtree(config_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
