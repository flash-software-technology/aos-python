"""The engine run by this process, for an application that keeps its users
in its own Postgres and deploys no separate auth server.

    from aos_auth.local import start_local

    local = start_local(database_url=..., master_key=..., app_url="https://shop.example.com")
    aos = local.async_client()                 # or local.client()
    app.mount("/aos", local.asgi())           # FastAPI/Starlette: the browser's routes

The SDK starts the engine program ("aos app") beside the application and
talks to it on a local address with a one-time key.
"""
from __future__ import annotations

import atexit
import hashlib
import io
import json
import os
import platform
import secrets
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .client import Aos, AsyncAos

ENGINE_VERSION = "v0.5.0"
"""The engine release this SDK is tested with."""


def _cache_dir() -> Path:
    if os.environ.get("AOSCTL_CACHE_DIR"):
        return Path(os.environ["AOSCTL_CACHE_DIR"])
    # The same place as Go's os.UserCacheDir, so aosctl and the SDKs share downloads.
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "aos"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "aos"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "aos"


def _target() -> tuple[str, str]:
    os_name = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(sys.platform)
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not os_name or not arch:
        raise RuntimeError(f"aos: no engine build for {sys.platform}/{platform.machine()}")
    return os_name, arch


def download_engine(version: str = ENGINE_VERSION) -> Path:
    """Downloads an engine release into the shared cache and returns its path."""
    os_name, arch = _target()
    exe = "aos.exe" if os_name == "windows" else "aos"
    path = _cache_dir() / "engine" / version / exe
    if path.exists():
        return path
    base = os.environ.get("AOSCTL_RELEASES_URL", "https://github.com/flash-software-technology/aos/releases/download").rstrip("/") + f"/{version}/"
    asset = f"aos_{version}_{os_name}_{arch}" + (".zip" if os_name == "windows" else ".tar.gz")

    def get(url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=300) as resp:  # noqa: S310 - fixed https base or an explicit override
            return resp.read()

    want = next((f[0] for f in (line.split() for line in get(base + "checksums.txt").decode().splitlines()) if len(f) == 2 and f[1] == asset), None)
    if not want:
        raise RuntimeError(f"aos: engine {version} has no build for {os_name}/{arch}")
    archive = get(base + asset)
    if hashlib.sha256(archive).hexdigest() != want:
        raise RuntimeError(f"aos: {asset} does not match its checksum; not using it")
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            name = next(n for n in z.namelist() if n.rsplit("/", 1)[-1] == exe)
            body = z.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as t:
            member = next(m for m in t.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] == exe)
            body = t.extractfile(member).read()  # type: ignore[union-attr]
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_suffix(path.suffix + ".part")
    part.write_bytes(body)
    part.chmod(0o755)
    part.replace(path)
    return path


@dataclass
class LocalEngine:
    url: str
    path: str
    publishable_key: str
    version: str
    _token: str = field(repr=False)
    _process: subprocess.Popen = field(repr=False)

    def client(self) -> Aos:
        """A synchronous SDK client, talking to the engine as the backend."""
        return Aos(self.url, self.publishable_key, self._token)

    def async_client(self) -> AsyncAos:
        return AsyncAos(self.url, self.publishable_key, self._token)

    def asgi(self) -> Any:
        """An ASGI app that passes the browser's routes to the engine.
        Mount it at the path: app.mount("/aos", local.asgi())."""
        import asyncio
        import weakref

        import httpx

        # One connection pool per event loop: a pool cannot cross loops.
        pools: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, httpx.AsyncClient]" = weakref.WeakKeyDictionary()
        base_url = self.url
        prefix = self.path

        def pool() -> httpx.AsyncClient:
            loop = asyncio.get_running_loop()
            c = pools.get(loop)
            if c is None or c.is_closed:
                c = pools[loop] = httpx.AsyncClient(base_url=base_url, timeout=30)
            return c

        async def app(scope: dict, receive: Any, send: Any) -> None:
            if scope["type"] != "http":
                return
            # Starlette keeps the mount prefix in "path" in newer versions,
            # and only in "root_path" in older ones.
            path = scope["path"]
            if not (path == prefix or path.startswith(prefix + "/")):
                path = prefix + path
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body"):
                    break
            headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"] if k.lower() not in (b"host", b"content-length")]
            # A browser never speaks for the backend.
            headers = [(k, v) for k, v in headers if not (k.lower() == "authorization" and "sk_local_" in v)]
            client = scope.get("client")
            if client:
                prior = next((v for k, v in headers if k.lower() == "x-forwarded-for"), "")
                headers = [(k, v) for k, v in headers if k.lower() != "x-forwarded-for"]
                headers.append(("x-forwarded-for", f"{prior}, {client[0]}" if prior else client[0]))
            query = scope.get("query_string", b"").decode()
            resp = await pool().request(scope["method"], path + ("?" + query if query else ""), headers=headers, content=body)
            out = [(k.encode(), v.encode()) for k, v in resp.headers.multi_items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")]
            await send({"type": "http.response.start", "status": resp.status_code, "headers": out})
            await send({"type": "http.response.body", "body": resp.content})

        return app

    def stop(self, timeout: float = 10) -> None:
        if self._process.poll() is not None:
            return
        try:
            self._process.stdin.close()  # type: ignore[union-attr]
            self._process.wait(timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()

    def __enter__(self) -> "LocalEngine":
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()


def start_local(*, database_url: str, master_key: str, app_url: str, path: str = "/aos", origins: list[str] | None = None,
                slug: str = "app", name: str = "App", kind: str = "multi", development: bool = False,
                engine: str | None = None, engine_version: str = ENGINE_VERSION, env: dict[str, str] | None = None,
                log: bool = True) -> LocalEngine:
    """Starts the engine for this application. Email settings go in env
    (AOS_SMTP_ADDR, AOS_SMTP_USERNAME, AOS_SMTP_PASSWORD, AOS_MAIL_FROM)."""
    program = engine or os.environ.get("AOS_ENGINE") or str(download_engine(engine_version))
    token = "sk_local_" + secrets.token_urlsafe(32)
    args = [program, "app", "--app-url", app_url, "--path", path, "--slug", slug, "--name", name, "--kind", kind, "--exit-with-stdin"]
    for o in origins or []:
        args += ["--origin", o]
    if development:
        args.append("--development")
    proc = subprocess.Popen(  # noqa: S603 - our own engine program
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None if log else subprocess.DEVNULL,
        env={**os.environ, **(env or {}), "AOS_DATABASE_URL": database_url, "AOS_MASTER_KEY": master_key, "AOS_LOCAL_TOKEN": token},
    )
    line = proc.stdout.readline().decode()  # type: ignore[union-attr]
    if not line:
        proc.wait(5)
        raise RuntimeError(f"aos: the engine stopped while starting (exit {proc.returncode}); see its log")
    ready = json.loads(line)
    local = LocalEngine(ready["url"], ready["path"], ready["publishable_key"], ready["version"], token, proc)
    atexit.register(local.stop)
    return local
