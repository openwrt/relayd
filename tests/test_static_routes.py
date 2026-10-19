#!/usr/bin/env python3
"""Exercise static gateway discovery using an isolated ARP responder."""

import argparse
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


GATEWAY = "192.0.2.1"
ADDRESS = "192.0.2.2"
GATEWAY_MAC = bytes.fromhex("020000000001")
BINARY = None
PRODUCTION_TIMERS = False


class StaticRoutes(unittest.TestCase):
    def ip(self, *args):
        return subprocess.check_output(["ip", *args], text=True)

    def wait_for(self, predicate, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process is not None:
                self.assertIsNone(self.process.poll(), "relayd exited unexpectedly")
            self.assertFalse(self.errors, self.errors)
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def setUp(self):
        self.process = None
        self.managed_local_address = True
        self.stop = threading.Event()
        self.enabled = True
        self.expected_source = ADDRESS
        self.probes = []
        self.errors = []
        self.log = tempfile.TemporaryFile(mode="w+")
        self.addCleanup(self.log.close)
        self.ip("link", "add", "rd-up", "type", "veth", "peer", "name", "rd-gw")
        self.addCleanup(self.ip, "link", "del", "rd-up")
        self.ip("link", "add", "rd-lan", "type", "dummy")
        self.addCleanup(self.ip, "link", "del", "rd-lan")
        for name in ["lo", "rd-up", "rd-gw", "rd-lan"]:
            self.ip("link", "set", name, "up")
        self.ip("address", "add", ADDRESS + "/24", "dev", "rd-up")
        self.ip("address", "add", "198.51.100.1/24", "dev", "rd-lan")
        address = json.loads(self.ip("-j", "link", "show", "rd-up"))[0]["address"]
        self.uplink_mac = bytes.fromhex(address.replace(":", ""))
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)
        )
        self.addCleanup(self.sock.close)
        self.sock.bind(("rd-gw", 0))
        self.sock.settimeout(0.1)
        self.thread = threading.Thread(target=self.respond, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_responder)
        self.addCleanup(self.stop_relay)

    def stop_responder(self):
        self.stop.set()
        self.thread.join(timeout=2)

    def stop_relay(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None

    def reply(self, source=GATEWAY, source_mac=GATEWAY_MAC, target=None):
        target = target or self.expected_source
        packet = self.uplink_mac + source_mac + b"\x08\x06"
        packet += struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        packet += source_mac + socket.inet_aton(source)
        packet += self.uplink_mac + socket.inet_aton(target)
        self.sock.send(packet)

    def respond(self):
        while not self.stop.is_set():
            try:
                packet = self.sock.recv(2048)
                if len(packet) < 42 or packet[12:14] != b"\x08\x06":
                    continue
                if packet[20:22] != b"\x00\x01":
                    continue
                if packet[38:42] != socket.inet_aton(GATEWAY):
                    continue
                source = socket.inet_ntoa(packet[28:32])
                self.probes.append(source)
                if self.enabled and source == self.expected_source:
                    self.reply(target=source)
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno in (errno.ENETDOWN, errno.ENETUNREACH):
                    self.stop.wait(0.01)
                    continue
                self.errors.append(str(exc))
                return

    def start_relay(self, routes=None, local_address=ADDRESS):
        args = [str(BINARY), "-I", "rd-up", "-I", "rd-lan", "-B", "-D"]
        self.managed_local_address = local_address is not None
        if local_address is not None:
            args += ["-L", local_address]
        if not PRODUCTION_TIMERS:
            args += ["-t", "2", "-p", "2"]
        args += routes if routes is not None else ["-G", GATEWAY]
        args += ["-d", "-d"]
        self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)

    def routes(self, destination="default"):
        return [
            route
            for route in json.loads(
                self.ip("-j", "-4", "route", "show", "table", "all")
            )
            if route.get("dst") == destination
            and route.get("gateway") == GATEWAY
            and route.get("dev") == "rd-up"
        ]

    def assert_routes(self, destination="default"):
        count = 2 if self.managed_local_address else 1
        self.assertTrue(
            self.wait_for(lambda: len(self.routes(destination)) == count),
            "configured route was not discovered in all relay tables",
        )

    def test_gateway_returns_after_expiry(self):
        self.start_relay()
        self.assert_routes()
        self.enabled = False
        self.ip("link", "set", "rd-gw", "down")
        self.assertTrue(
            self.wait_for(
                lambda: not self.routes(), timeout=40 if PRODUCTION_TIMERS else 7
            ),
            "unreachable gateway did not expire",
        )
        self.enabled = True
        self.ip("link", "set", "rd-gw", "up")
        self.assert_routes()

    def test_gateway_missing_at_startup(self):
        self.enabled = False
        self.start_relay()
        self.assertTrue(self.wait_for(lambda: bool(self.probes)))
        self.assertEqual(self.routes(), [])
        self.enabled = True
        self.assert_routes()

    def test_ipv4_address_assigned_after_startup(self):
        self.ip("address", "del", ADDRESS + "/24", "dev", "rd-up")
        self.start_relay()
        self.assertTrue(self.wait_for(lambda: "1.1.1.1" in self.probes))
        self.assertEqual(self.routes(), [])
        self.ip("address", "add", ADDRESS + "/24", "dev", "rd-up")
        self.assert_routes()
        self.assertIn(ADDRESS, self.probes)

    def test_ipv4_address_changes(self):
        # -L pins a separate local route source; it must not reference an
        # address that this test deliberately removes from the interface.
        self.start_relay(local_address=None)
        self.assert_routes()
        self.expected_source = "192.0.2.3"
        self.ip("address", "del", ADDRESS + "/24", "dev", "rd-up")
        self.ip("address", "add", self.expected_source + "/24", "dev", "rd-up")
        self.assertTrue(
            self.wait_for(
                lambda: self.expected_source in self.probes,
                timeout=37 if PRODUCTION_TIMERS else 4,
            ),
            "ARP probes retained the old interface address",
        )
        self.assert_routes()

    def test_explicit_static_route(self):
        destination = "203.0.113.0/24"
        self.enabled = False
        self.start_relay(["-R", GATEWAY + ":" + destination])
        self.assertTrue(self.wait_for(lambda: bool(self.probes)))
        self.assertEqual(self.routes(destination), [])
        self.enabled = True
        self.assert_routes(destination)
        self.assertEqual(self.routes(), [])

    def test_address_reassigned_before_gateway_expires(self):
        self.start_relay()
        self.assert_routes()
        self.ip("address", "del", ADDRESS + "/24", "dev", "rd-up")
        self.ip("address", "add", ADDRESS + "/24", "dev", "rd-up")
        self.assert_routes()

    def test_healthy_gateway_has_no_extra_probes(self):
        self.start_relay()
        self.assert_routes()
        time.sleep(0.2)
        count = len(self.probes)
        time.sleep(1.3)
        self.assertEqual(
            len(self.probes),
            count,
            "static discovery reprobed an already known gateway",
        )
        self.assertEqual(len(self.routes()), 2)

    def test_ordinary_host_still_expires(self):
        self.start_relay()
        self.assert_routes()
        host = "192.0.2.99"
        self.reply(source=host, source_mac=bytes.fromhex("020000000063"))

        def host_routes():
            return [
                r
                for r in json.loads(
                    self.ip("-j", "-4", "route", "show", "table", "all")
                )
                if r.get("dst") == host
                and r.get("dev") == "rd-up"
                and r.get("table") in ("16800", "16801", 16800, 16801)
            ]

        self.assertTrue(self.wait_for(lambda: len(host_routes()) == 2))
        self.assertTrue(
            self.wait_for(
                lambda: not host_routes(), timeout=40 if PRODUCTION_TIMERS else 7
            )
        )
        self.assertEqual(len(self.routes()), 2)

    def test_no_static_routes_has_no_discovery_timer(self):
        self.start_relay([])
        time.sleep(1.5)
        self.assertFalse(self.probes)
        self.assertEqual(self.routes(), [])


def main():
    global BINARY, PRODUCTION_TIMERS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--production-timers", action="store_true")
    parser.add_argument("--parent-netns", type=int, help=argparse.SUPPRESS)
    args, tests = parser.parse_known_args()
    BINARY = args.binary.resolve(strict=True)
    PRODUCTION_TIMERS = args.production_timers
    namespace = os.stat("/proc/self/ns/net").st_ino
    if args.parent_netns is None:
        # All link changes and synthetic traffic must stay off the host network.
        command = [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            sys.executable,
            str(Path(__file__).resolve()),
            "--binary",
            str(BINARY),
            "--parent-netns",
            str(namespace),
        ]
        if PRODUCTION_TIMERS:
            command.append("--production-timers")
        return subprocess.call(command + tests)
    if namespace == args.parent_netns:
        parser.error("refusing to run outside a new network namespace")
    unittest.main(argv=[sys.argv[0], *tests], verbosity=2)


if __name__ == "__main__":
    sys.exit(main())
