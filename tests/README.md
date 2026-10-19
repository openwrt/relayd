# Static gateway regression tests

Build relayd normally with CMake and libubox, then run:

```sh
python3 tests/test_static_routes.py --binary /absolute/path/to/relayd
```

The test needs Linux, Python 3, `ip` (iproute2), `unshare` (util-linux), and
permission to create user/network namespaces. It creates its own namespace
before changing links or sending packets. It requires neither root on the
host nor third-party Python modules. No network access is needed during tests.

A synthetic ARP responder on a veth peer answers gateway requests only when
they use the currently assigned uplink IPv4 address. Tests cover a gateway
returning after link loss and host expiry, an initially unavailable gateway,
late/changed IPv4 addresses, address reassignment before gateway expiry,
`-R` routes, healthy gateway probe traffic,
ordinary host expiry, and operation without static routes.

The default run uses `-t 2 -p 2` to shorten host expiry. To exercise link loss
with relayd's unchanged default timers:

```sh
python3 tests/test_static_routes.py --binary /absolute/path/to/relayd \
    --production-timers StaticRoutes.test_gateway_returns_after_expiry
```

The same tests can be run against an unpatched binary to demonstrate the
regression. Recovery tests deliberately fail on the original implementation;
they do not inject unsolicited ARP replies or restart relayd to restore routes.
