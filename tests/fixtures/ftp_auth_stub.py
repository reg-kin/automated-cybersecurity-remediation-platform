#!/usr/bin/env python3
"""Authentication-only Stage 2 fixture; never exposes files or data sockets.

Usage: python3 tests/fixtures/ftp_auth_stub.py BIND_IPV4 PERMITTED_IPV4 MODE
MODE is reject (530) or accept (simulated 230). Always listens on TCP 2121.
Run only in the separately authorized controlled test window described in
 docs/nmap-stage2-controlled-test-plan.md. Stop the foreground process with Ctrl-C.
"""

import argparse
import ipaddress
import socket
import socketserver
import time

PORT = 2121
IDLE_TIMEOUT = 10.0
SESSION_TIMEOUT = 30.0
MAX_COMMANDS = 32
MAX_LINE = 1024


def explicit_ipv4(value):
    """Require a literal unicast IPv4 address, never wildcard or a hostname."""
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("expected an explicit IPv4 address") from exc
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise ValueError("wildcard, multicast and broadcast addresses are forbidden")
    return str(address)


class AuthHandler(socketserver.StreamRequestHandler):
    def handle(self):
        deadline = time.monotonic() + SESSION_TIMEOUT
        user_pending = False
        try:
            self.wfile.write(b"220 Stage2 FTP authentication fixture\r\n")
            for _ in range(MAX_COMMANDS):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                self.connection.settimeout(min(IDLE_TIMEOUT, remaining))
                line = self.rfile.readline(MAX_LINE + 1)
                if not line or len(line) > MAX_LINE or not line.endswith(b"\r\n"):
                    return
                parts = line[:-2].split(b" ", 1)
                verb = parts[0].upper()
                argument = parts[1] if len(parts) == 2 else b""
                if verb == b"QUIT":
                    self.wfile.write(b"221 Goodbye\r\n")
                    return
                if verb == b"USER":
                    user_pending = argument.lower() == b"anonymous"
                    response = (b"331 Password required\r\n" if user_pending
                                else b"530 Only anonymous test login supported\r\n")
                elif verb == b"PASS":
                    if not user_pending:
                        response = b"503 Send USER anonymous first\r\n"
                    elif self.server.mode == "reject":
                        response = b"530 Anonymous login disabled\r\n"
                    else:
                        response = b"230 Simulated anonymous login accepted\r\n"
                    user_pending = False
                else:
                    response = b"502 Unsupported by authentication-only fixture\r\n"
                self.wfile.write(response)
        except (OSError, TimeoutError):
            # Idle clients, probes and disconnects must not emit tracebacks.
            return


class AuthServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, bind_ip, permitted_source, mode):
        bind_ip = explicit_ipv4(bind_ip)
        self.permitted_source = explicit_ipv4(permitted_source)
        if mode not in ("reject", "accept"):
            raise ValueError("mode must be reject or accept")
        self.mode = mode
        super().__init__((bind_ip, PORT), AuthHandler)

    def verify_request(self, request, client_address):
        return client_address[0] == self.permitted_source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bind_ipv4", help="explicit local IPv4 address (no wildcard)")
    parser.add_argument("permitted_ipv4", help="only permitted client source IPv4")
    parser.add_argument("mode", choices=("reject", "accept"))
    args = parser.parse_args(argv)
    try:
        with AuthServer(args.bind_ipv4, args.permitted_ipv4, args.mode) as server:
            try:
                server.serve_forever(poll_interval=0.1)
            except KeyboardInterrupt:
                pass
    except (ValueError, OSError) as exc:
        parser.exit(2, f"ftp_auth_stub: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
