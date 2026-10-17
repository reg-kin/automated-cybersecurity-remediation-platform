"""Offline socket tests. No scanners, application imports or external hosts."""

import contextlib
import ftplib
import importlib.util
from pathlib import Path
import socket
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "ftp_auth_stub", Path(__file__).parent / "fixtures" / "ftp_auth_stub.py"
)
stub = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stub)


@contextlib.contextmanager
def running(mode="reject", permitted="127.0.0.1"):
    with stub.AuthServer("127.0.0.1", permitted, mode) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=2)
            assert not thread.is_alive()


@contextlib.contextmanager
def client():
    with socket.create_connection(("127.0.0.1", 2121), timeout=2) as connection:
        with connection.makefile("rb") as reader:
            assert reader.readline().startswith(b"220 ")
            yield connection, reader


class FTPAuthStubTests(unittest.TestCase):
    def test_ftplib_accept_and_reject(self):
        for mode in ("accept", "reject"):
            with self.subTest(mode=mode), running(mode), ftplib.FTP() as ftp:
                ftp.connect("127.0.0.1", 2121, timeout=2)
                if mode == "accept":
                    self.assertTrue(ftp.login().startswith("230 "))
                else:
                    with self.assertRaisesRegex(ftplib.error_perm, "^530 "):
                        ftp.login()
                self.assertTrue(ftp.quit().startswith("221 "))

    def test_bind_is_exact_and_fixed(self):
        with running() as server:
            self.assertEqual(server.socket.getsockname(), ("127.0.0.1", 2121))
            self.assertEqual(server.address_family, socket.AF_INET)

    def test_disallowed_source_gets_no_banner(self):
        with running(permitted="127.0.0.2"):
            with socket.create_connection(("127.0.0.1", 2121), timeout=2) as connection:
                self.assertEqual(connection.recv(1024), b"")

    def test_invalid_configuration(self):
        for address in ("0.0.0.0", "::1", "localhost", "224.0.0.1", "255.255.255.255"):
            for bind, permitted in ((address, "127.0.0.1"), ("127.0.0.1", address)):
                with self.subTest(bind=bind, permitted=permitted), self.assertRaises(ValueError):
                    stub.AuthServer(bind, permitted, "reject")
        with self.assertRaises(ValueError):
            stub.AuthServer("127.0.0.1", "127.0.0.1", "invalid")

    def test_unsupported_commands_and_auth_sequence(self):
        with running("accept"), client() as (connection, reader):
            commands = [(b"PASS anything", b"503"), (b"USER root", b"530"),
                        (b"PASS secret", b"503"), (b"USER anonymous", b"331"),
                        (b"PASS test@example.invalid", b"230")]
            commands += [(verb, b"502") for verb in
                         (b"PASV", b"EPSV", b"PORT 127,0,0,1,1,1", b"EPRT x",
                          b"LIST", b"RETR /etc/passwd", b"STOR file", b"DELE file",
                          b"SYST", b"FEAT", b"", b"SITE EXEC id")]
            for command, code in commands:
                connection.sendall(command + b"\r\n")
                self.assertTrue(reader.readline().startswith(code), command)

    def test_idle_timeout(self):
        with patch.object(stub, "IDLE_TIMEOUT", 0.05), running(), client() as (_, reader):
            self.assertEqual(reader.readline(), b"")

    def test_session_timeout(self):
        with patch.object(stub, "SESSION_TIMEOUT", 0.05), running(), client() as (_, reader):
            self.assertEqual(reader.readline(), b"")

    def test_oversized_and_unterminated_lines_close(self):
        for line in (b"X" * 1025, b"USER anonymous\n"):
            with self.subTest(line_length=len(line)), running(), client() as (connection, reader):
                connection.sendall(line)
                self.assertEqual(reader.readline(), b"")

    def test_command_limit(self):
        with patch.object(stub, "MAX_COMMANDS", 2), running(), client() as (connection, reader):
            connection.sendall(b"NOOP\r\nNOOP\r\n")
            self.assertTrue(reader.readline().startswith(b"502"))
            self.assertTrue(reader.readline().startswith(b"502"))
            self.assertEqual(reader.readline(), b"")

    def test_ctrl_c_closes_listener(self):
        with patch.object(stub.AuthServer, "serve_forever", side_effect=KeyboardInterrupt):
            self.assertEqual(stub.main(["127.0.0.1", "127.0.0.1", "reject"]), 0)
        with running():
            pass  # Rebinding proves the interrupted main closed its listener.


if __name__ == "__main__":
    unittest.main()
