"""Serve the local-only password security lab."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
PAGE = ROOT / "password-lab.html"
MAX_REQUEST_SIZE = 4096

spec = importlib.util.spec_from_file_location("password_gen", ROOT / "password-gen.py")
if spec is None or spec.loader is None:
    raise RuntimeError("Could not load password-gen.py.")
password_gen = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = password_gen
spec.loader.exec_module(password_gen)


class LabRequestHandler(BaseHTTPRequestHandler):
    server_version = "PasswordLab/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        """Log request metadata, but never request bodies."""
        print(f"{self.address_string()} - {format % args}", file=sys.stderr)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
            "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def do_GET(self) -> None:
        if urlsplit(self.path).path != "/":
            self._json(404, {"error": "Not found."})
            return
        try:
            page = PAGE.read_bytes()
        except OSError as error:
            self._json(500, {"error": f"Could not load the demo page: {error}"})
            return
        self._send(200, "text/html; charset=utf-8", page)

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/api/generate":
            self._json(404, {"error": "Not found."})
            return

        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        if origin is None:
            local_hosts = {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
            if host not in local_hosts:
                self._json(403, {"error": "Use the local address shown in the terminal."})
                return
        else:
            parsed_origin = urlsplit(origin)
            if (
                parsed_origin.scheme not in {"http", "https"}
                or parsed_origin.netloc.lower() != host.lower()
                or parsed_origin.path
                or parsed_origin.query
                or parsed_origin.fragment
                or parsed_origin.username is not None
                or parsed_origin.password is not None
            ):
                self._json(403, {"error": "Cross-origin requests are not allowed."})
                return

        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._json(400, {"error": "A valid Content-Length header is required."})
            return
        if not 0 < content_length <= MAX_REQUEST_SIZE:
            self._json(400, {"error": "Request body is missing or too large."})
            return

        try:
            data = json.loads(self.rfile.read(content_length))
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")
            if set(data) - {
                "length",
                "use_lowercase",
                "use_uppercase",
                "use_digits",
                "use_symbols",
                "avoid_ambiguous",
            }:
                raise ValueError("Unexpected password options.")
            if any(
                key in data and type(data[key]) is not bool
                for key in (
                    "use_lowercase",
                    "use_uppercase",
                    "use_digits",
                    "use_symbols",
                    "avoid_ambiguous",
                )
            ):
                raise ValueError("Character options must be true or false.")
            if "length" in data and type(data["length"]) is not int:
                raise ValueError("Length must be a whole number.")

            options = password_gen.PasswordOptions(**data)
            options.validate()
            pool = options.character_pool()
            password = password_gen.generate_password(
                length=options.length,
                use_lowercase=options.use_lowercase,
                use_uppercase=options.use_uppercase,
                use_digits=options.use_digits,
                use_symbols=options.use_symbols,
                avoid_ambiguous=options.avoid_ambiguous,
            )
            entropy, strength = password_gen.estimate_strength(password, pool)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as error:
            self._json(400, {"error": str(error)})
            return

        self._json(
            200,
            {
                "password": password,
                "length": len(password),
                "entropy_bits": entropy,
                "strength": strength,
            },
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local password security lab.")
    parser.add_argument("--port", type=int, default=8000, help="local port (default: 8000)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    try:
        server = HTTPServer(("127.0.0.1", args.port), LabRequestHandler)
    except OSError as error:
        parser.error(f"could not start local server: {error}")

    print(f"Password Security Lab is running at http://127.0.0.1:{server.server_port}")
    print("Local-only demo. Stop with Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Password Security Lab.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
