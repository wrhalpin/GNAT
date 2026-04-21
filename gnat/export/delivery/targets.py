# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
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
        """Initialize FileDelivery."""
        self._dir = Path(output_dir)
        self._atomic = atomic
        self._encoding = encoding

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
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
        """Return unambiguous string representation."""
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
        """Initialize HTTPDelivery."""
        self._url = url
        self._headers = {"Content-Type": content_type, **(headers or {})}
        self._auth = auth
        self._timeout = timeout
        self._per_url = per_payload_url or {}
        self._success_codes = set(success_codes or [200, 201, 204])

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
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
        """Return unambiguous string representation."""
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
        """Initialize EDLServer."""
        self._host = host
        self._port = port
        self._files: dict[str, str] = {}
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
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
        """Internal helper for start."""
        import http.server

        files_ref = self._files
        lock_ref = self._lock

        class _H(http.server.BaseHTTPRequestHandler):
            """_H implementation."""

            def do_GET(self):
                """Do get."""
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
                """Log message."""
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
        """Stop the EDLServer."""
        if self._server:
            self._server.shutdown()
            self._server = None

    def url(self, filename: str = "") -> str:
        """Url."""
        host = "localhost" if self._host in ("0.0.0.0", "") else self._host  # nosec B104 — comparing, not binding
        return f"http://{host}:{self._port}/{filename}"

    def __repr__(self) -> str:
        """Return unambiguous string representation."""
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
        """Initialize PlatformDelivery."""
        self._client = client

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
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
        """Return unambiguous string representation."""
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
        """Initialize MultiDelivery."""
        if len(targets) < 2:
            raise ValueError("MultiDelivery requires at least two targets")
        self._targets = list(targets)

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
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
        """Return unambiguous string representation."""
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
        """Initialize LogDelivery."""
        self._level = getattr(logging, level.upper(), logging.DEBUG)
        self._max = max_chars

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
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
        """Return unambiguous string representation."""
        return "LogDelivery()"


class TAXIIPushDelivery(ExportDelivery):
    """
    Push STIX bundles to a remote GNAT TAXII 2.1 collection endpoint.

    Wraps :class:`HTTPDelivery` with TAXII-specific Content-Type and
    Accept headers, and serialises the ``"objects"`` payload key as a
    proper STIX bundle.

    Parameters
    ----------
    taxii_url : str
        Base URL of the remote GNAT TAXII server
        (e.g. ``"https://gnat-east.acme.com/taxii2/"``).
    workspace : str
        Target workspace (collection) name on the remote instance.
    api_key : str
        Bearer token for the remote TAXII server.
    verify_ssl : bool
        Verify TLS certificates.  Default ``True``.
    timeout : int
        Request timeout seconds.  Default ``30``.

    Examples
    --------
    ::

        delivery = TAXIIPushDelivery(
            taxii_url="https://gnat-east.acme.com/taxii2/",
            workspace="threats-2025",
            api_key="Bearer peer-token",
        )
        result = delivery.deliver(transform_result)
    """

    _TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
    _STIX_MEDIA_TYPE = "application/stix+json;version=2.1"
    _TAXII_ROOT = "/taxii2/roots/gnat"

    def __init__(
        self,
        taxii_url: str,
        workspace: str,
        api_key: str,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        """Initialize TAXIIPushDelivery."""

        self._taxii_url = taxii_url.rstrip("/")
        self._workspace = workspace
        self._api_key = api_key.strip()
        if self._api_key and not self._api_key.startswith("Bearer "):
            self._api_key = f"Bearer {self._api_key}"
        self._verify_ssl = verify_ssl
        self._timeout = timeout

    def deliver(self, result: TransformResult) -> DeliveryResult:
        """Deliver data to the configured target."""
        import uuid

        objects = result.payloads.get("objects", [])
        if not objects:
            # Try to collect from all payloads that are lists of dicts
            for payload in result.payloads.values():
                if isinstance(payload, list):
                    objects.extend(payload)

        if not objects:
            dr = DeliveryResult()
            logger.debug(
                "TAXIIPushDelivery: no objects to push to %s/%s", self._taxii_url, self._workspace
            )
            return dr

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects if isinstance(objects, list) else [objects],
        }

        # Build endpoint URL
        host = self._taxii_url
        for suffix in ("/taxii2", "/taxii2/"):
            if host.endswith(suffix):
                host = host[: -len(suffix)]
                break
        endpoint = f"{host}{self._TAXII_ROOT}/collections/{self._workspace}/objects/"

        inner = HTTPDelivery(
            url=endpoint,
            headers={
                "Authorization": self._api_key,
                "Accept": self._TAXII_MEDIA_TYPE,
                "Content-Type": self._STIX_MEDIA_TYPE,
            },
            verify_ssl=self._verify_ssl,
            timeout=self._timeout,
            success_codes=[200, 201, 202, 204],
        )

        inner_result = TransformResult()
        inner_result.payloads["bundle"] = bundle

        dr = inner.deliver(inner_result)
        # Re-map payload name for clarity
        dr.delivered = [f"{self._workspace}/bundle"] if dr.delivered else []
        return dr

    def __repr__(self) -> str:
        """Return unambiguous string representation."""
        return f"TAXIIPushDelivery(taxii_url={self._taxii_url!r}, workspace={self._workspace!r})"
