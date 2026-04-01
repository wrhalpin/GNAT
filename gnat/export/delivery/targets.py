"""
gnat.export.delivery.targets
================================

Concrete ExportDelivery implementations for file, HTTP, EDL server,
platform connector, multi-target fan-out, and logging.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from gnat.export.base import DeliveryResult, ExportDelivery, TransformResult
from gnat.utils.url_security import validate_url_scheme

if TYPE_CHECKING:
    from gnat.client import GNATClient

logger = logging.getLogger(__name__)


class FileDelivery(ExportDelivery):
    """
    Write transform payloads to files on the local filesystem.

    Uses atomic replace (write to temp file, then rename) so consumers
    never see a partial file mid-write.

    Parameters
    ----------
    output_dir : str or Path
        Directory to write files into.  Created if it does not exist.
    atomic : bool
        Use atomic write-then-rename.  Default ``True``.
    encoding : str
        Text encoding.  Default ``"utf-8"``.

    Examples
    --------
    ::

        delivery = FileDelivery("/var/www/edl/")
    """

    def __init__(
        self,
        output_dir: str,
        atomic: bool = True,
        encoding: str = "utf-8",
    ):
        self._dir = Path(output_dir)
        self._atomic = atomic
        self._encoding = encoding

    def deliver(self, result: TransformResult) -> DeliveryResult:
        self._dir.mkdir(parents=True, exist_ok=True)
        dr = DeliveryResult()

        for name, content in result.payloads.items():
            dest = self._dir / name
            try:
                if isinstance(content, (dict, list)):
                    body = json.dumps(content, indent=2).encode(self._encoding)
                elif isinstance(content, str):
                    body = content.encode(self._encoding)
                else:
                    body = content  # bytes

                if self._atomic:
                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self._dir, prefix=f".{name}.tmp")
                    try:
                        os.write(tmp_fd, body)
                        os.fsync(tmp_fd)
                    finally:
                        os.close(tmp_fd)
                    os.replace(tmp_path, dest)
                else:
                    dest.write_bytes(body)

                dr.delivered.append(name)
                dr.metadata[name] = str(dest)
                logger.info("FileDelivery: %s → %s", name, dest)

            except Exception as exc:  # noqa: BLE001
                dr.failed.append(name)
                dr.errors.append(f"{name}: {exc}")
                dr.success = False
                logger.error("FileDelivery: failed %s — %s", name, exc)

        return dr

    def __repr__(self) -> str:
        return f"FileDelivery(dir={self._dir!r})"


class HTTPDelivery(ExportDelivery):
    """
    POST each transform payload to an HTTP endpoint.

    Parameters
    ----------
    url : str
        Target URL.
    headers : dict, optional
        Additional HTTP headers (e.g. ``{"Authorization": "Bearer <tok>"}"``).
    auth : tuple, optional
        ``(username, password)`` for HTTP Basic auth.
    content_type : str
        Content-Type.  Default ``"application/json"``.
    verify_ssl : bool
        Verify TLS.  Default ``True``.
    timeout : int
        Request timeout seconds.  Default ``30``.
    per_payload_url : dict, optional
        Override URL per payload name.
    success_codes : list of int
        HTTP status codes considered successful.  Default ``[200, 201, 204]``.

    Examples
    --------
    ::

        # Netskope CE
        delivery = HTTPDelivery(
            url="https://netskope-ce.example.com/api/plugin/threatintel/pushData",
            headers={"Authorization": "Bearer <token>"},
        )
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        auth: tuple | None = None,
        content_type: str = "application/json",
        verify_ssl: bool = True,
        timeout: int = 30,
        per_payload_url: dict[str, str] | None = None,
        success_codes: list[int] | None = None,
    ):
        self._url = url
        self._headers = {"Content-Type": content_type, **(headers or {})}
        self._auth = auth
        self._timeout = timeout
        self._per_url = per_payload_url or {}
        self._success_codes = set(success_codes or [200, 201, 204])

    def deliver(self, result: TransformResult) -> DeliveryResult:
        import base64
        import urllib.error
        import urllib.request

        dr = DeliveryResult()
        for name, content in result.payloads.items():
            target_url = self._per_url.get(name, self._url)

            if isinstance(content, (dict, list)):
                body = json.dumps(content).encode()
            elif isinstance(content, str):
                body = content.encode("utf-8")
            else:
                body = content

            validate_url_scheme(target_url)
            req = urllib.request.Request(
                target_url,
                data=body,
                method="POST",
                headers=dict(self._headers),
            )
            if self._auth:
                creds = base64.b64encode(f"{self._auth[0]}:{self._auth[1]}".encode()).decode()
                req.add_header("Authorization", f"Basic {creds}")

            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310  # nosemgrep
                    status = resp.getcode()
                if status in self._success_codes:
                    dr.delivered.append(name)
                    dr.metadata[name] = {"url": target_url, "status": status}
                    logger.info("HTTPDelivery: %s → %s [%d]", name, target_url, status)
                else:
                    dr.failed.append(name)
                    dr.errors.append(f"{name}: status {status}")
                    dr.success = False

            except urllib.error.HTTPError as exc:
                dr.failed.append(name)
                dr.errors.append(f"{name}: HTTP {exc.code} {exc.reason}")
                dr.success = False
                logger.error("HTTPDelivery: %s → HTTP %d", name, exc.code)
            except Exception as exc:  # noqa: BLE001
                dr.failed.append(name)
                dr.errors.append(f"{name}: {exc}")
                dr.success = False
                logger.error("HTTPDelivery: %s failed — %s", name, exc)

        return dr

    def __repr__(self) -> str:
        return f"HTTPDelivery(url={self._url!r})"


class EDLServer(ExportDelivery):
    """
    Built-in HTTP server that serves EDL files to firewalls.

    On first :meth:`deliver` the server starts (background thread).
    Subsequent delivers update files in-memory — the server always serves
    the latest version.

    Firewalls poll ``http://<host>:<port>/<filename>`` on their schedule.

    Parameters
    ----------
    host : str
        Bind address.  Default ``"0.0.0.0"``.
    port : int
        Port.  Default ``8080``.

    Examples
    --------
    ::

        server = EDLServer(port=8080)
        # Palo Alto config: EDL URL → http://<host>:8080/indicators-ipv4.txt
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):  # nosec B104 — overridable via --host flag
        self._host = host
        self._port = port
        self._files: dict[str, str] = {}
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    def deliver(self, result: TransformResult) -> DeliveryResult:
        with self._lock:
            for name, content in result.payloads.items():
                if isinstance(content, bytes):
                    self._files[name] = content.decode("utf-8", errors="replace")
                elif isinstance(content, str):
                    self._files[name] = content
                else:
                    self._files[name] = json.dumps(content)

        if self._server is None:
            self._start()

        dr = DeliveryResult()
        host = "localhost" if self._host in ("0.0.0.0", "") else self._host  # nosec B104 — comparing, not binding
        for name in result.payloads:
            url = f"http://{host}:{self._port}/{name}"
            dr.delivered.append(name)
            dr.metadata[name] = url
            logger.info("EDLServer: %s available at %s", name, url)
        return dr

    def _start(self) -> None:
        import http.server

        files_ref = self._files
        lock_ref = self._lock

        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.strip("/")
                with lock_ref:
                    content = files_ref.get(path)
                if content is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                logger.debug("EDLServer: " + fmt, *args)

        self._server = http.server.HTTPServer((self._host, self._port), _H)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name=f"gnat-edl:{self._port}",
        )
        self._thread.start()
        logger.info("EDLServer started on %s:%d", self._host, self._port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None

    def url(self, filename: str = "") -> str:
        host = "localhost" if self._host in ("0.0.0.0", "") else self._host  # nosec B104 — comparing, not binding
        return f"http://{host}:{self._port}/{filename}"

    def __repr__(self) -> str:
        return f"EDLServer(port={self._port})"


class PlatformDelivery(ExportDelivery):
    """
    Push objects through an existing GNATClient connector.

    Calls ``client.client.upsert_object()`` for each object in the
    ``"objects"`` payload or the ``bundle.json`` payload.

    Parameters
    ----------
    client : GNATClient
        Connected platform client.

    Examples
    --------
    ::

        delivery = PlatformDelivery(xsoar_client)
    """

    def __init__(self, client: GNATClient):
        self._client = client

    def deliver(self, result: TransformResult) -> DeliveryResult:
        objects = result.payloads.get("objects", [])
        if not objects:
            bundle_raw = result.payloads.get("bundle.json")
            if bundle_raw:
                bundle = json.loads(bundle_raw) if isinstance(bundle_raw, str) else bundle_raw
                objects = bundle.get("objects", [])

        dr = DeliveryResult()
        written = 0
        for obj in objects:
            try:
                stix_dict = obj.to_dict() if hasattr(obj, "to_dict") else obj
                native = self._client.client.from_stix(stix_dict)
                self._client.client.upsert_object(stix_dict.get("type", ""), native)
                written += 1
            except Exception as exc:  # noqa: BLE001
                dr.errors.append(str(exc))
                dr.success = False

        dr.delivered.append(f"{written} objects")
        dr.metadata["written"] = written
        return dr

    def __repr__(self) -> str:
        return f"PlatformDelivery(target={getattr(self._client, 'target', '?')!r})"


class MultiDelivery(ExportDelivery):
    """
    Fan out the same payload to multiple delivery targets.

    All targets attempt delivery even if one fails.

    Parameters
    ----------
    *targets : ExportDelivery
        Two or more delivery targets.

    Examples
    --------
    ::

        delivery = MultiDelivery(
            FileDelivery("/var/www/edl/"),
            HTTPDelivery("https://backup/update"),
        )
    """

    def __init__(self, *targets: ExportDelivery):
        if len(targets) < 2:
            raise ValueError("MultiDelivery requires at least two targets")
        self._targets = list(targets)

    def deliver(self, result: TransformResult) -> DeliveryResult:
        combined = DeliveryResult()
        for target in self._targets:
            dr = target.deliver(result)
            combined.delivered.extend(dr.delivered)
            combined.failed.extend(dr.failed)
            combined.errors.extend(dr.errors)
            combined.metadata[repr(target)] = dr.metadata
            if not dr.success:
                combined.success = False
        return combined

    def __repr__(self) -> str:
        return f"MultiDelivery(n={len(self._targets)})"


class LogDelivery(ExportDelivery):
    """
    Log payload content via the Python logger (debug/test use).

    Parameters
    ----------
    level : str
        Log level.  Default ``"debug"``.
    max_chars : int
        Maximum characters to log per payload.  Default ``500``.
    """

    def __init__(self, level: str = "debug", max_chars: int = 500):
        self._level = getattr(logging, level.upper(), logging.DEBUG)
        self._max = max_chars

    def deliver(self, result: TransformResult) -> DeliveryResult:
        dr = DeliveryResult()
        for name, content in result.payloads.items():
            if isinstance(content, bytes):
                body = content.decode("utf-8", errors="replace")[: self._max]
            elif isinstance(content, (dict, list)):
                try:
                    body = json.dumps(content)[: self._max]
                except (TypeError, ValueError):
                    body = str(content)[: self._max]
            else:
                body = str(content)[: self._max]
            logger.log(self._level, "LogDelivery[%s]: %s", name, body)
            dr.delivered.append(name)
        return dr

    def __repr__(self) -> str:
        return "LogDelivery()"
