#!/usr/bin/env python3
"""
Raw Reticulum Resource receiver — validates Link + Resource transfer
between Rust (leviculum) and Python (RNS) at the transport level.

This creates a destination, listens for incoming links, accepts resources,
and prints what it receives.
"""

import json
import os
import shutil
import signal
import sys
import tempfile
import time

import RNS

received_resources = []

def link_established(link):
    """Called when a link is established."""
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_resource_started_callback(resource_started)
    link.set_resource_concluded_callback(resource_concluded)
    print(json.dumps({
        "event": "link_established",
        "link_hash": RNS.hexrep(link.hash, delimit=False),
    }), flush=True)

def resource_started(resource):
    print(json.dumps({
        "event": "resource_started",
        "size": resource.total_size,
        "hash": RNS.hexrep(resource.hash, delimit=False),
    }), flush=True)

def resource_concluded(resource):
    if resource.status == RNS.Resource.COMPLETE:
        data = resource.data.read()
        print(json.dumps({
            "event": "resource_complete",
            "size": len(data),
            "hash": RNS.hexrep(resource.hash, delimit=False),
            "data_preview": data[:200].decode("utf-8", errors="replace"),
        }), flush=True)
        received_resources.append(data)
    else:
        print(json.dumps({
            "event": "resource_failed",
            "status": str(resource.status),
        }), flush=True)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=14967)
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()

    config_dir = tempfile.mkdtemp(prefix="rns_res_test_")

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

    try:
        reticulum = RNS.Reticulum(
            configdir=os.path.join(config_dir, "reticulum"),
            loglevel=RNS.LOG_WARNING,
        )

        identity = RNS.Identity()
        destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE,
            "lxmf", "delivery"
        )
        destination.set_link_established_callback(link_established)

        # Announce
        destination.announce()

        dest_hash = RNS.hexrep(destination.hash, delimit=False)
        signing_key = identity.get_public_key()[32:64].hex()

        print(json.dumps({
            "event": "ready",
            "destination_hash": dest_hash,
            "signing_key": signing_key,
            "port": args.port,
        }), flush=True)

        def handle_signal(sig, frame):
            print(json.dumps({
                "event": "shutdown",
                "resources_received": len(received_resources),
            }), flush=True)
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        deadline = time.time() + args.timeout
        while time.time() < deadline:
            time.sleep(0.5)

        print(json.dumps({
            "event": "timeout",
            "resources_received": len(received_resources),
        }), flush=True)

    finally:
        shutil.rmtree(config_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
