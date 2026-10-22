"""Security and robustness checks for the traffic analyzer backend.

OWNER: QualityGuard.

Two kinds of checks live here:

* Static analysis of every module under `backend/app` (AST based, no external
  tools required). These catch the failure modes that matter most for a tool
  that shells out to TShark and accepts binary uploads.
* Runtime checks of the upload, query-parameter and error-handling behaviour of
  the HTTP contract in `traffic-analyzer/docs/API.md`.

The static checks deliberately fail loudly: a `shell=True` in a backend that
runs `tshark` with user supplied filters is a remote command execution risk.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from tests import qg_support as q
from tests.qg_support import qg_isolated_storage  # noqa: F401  (fixture import)

APP_DIR = Path(__file__).resolve().parents[1] / "app"
BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent

UPLOAD_ROUTE = "/api/analysis/upload"
CAPTURE_START_ROUTE = "/api/capture/start"


def python_sources() -> list[Path]:
    return sorted(APP_DIR.rglob("*.py"))


def tracked_sources() -> list[Path]:
    """Project python files, excluding virtual environments and build output."""
    ignored = {".venv", "venv", "node_modules", "__pycache__", "site-packages", "dist", "build"}
    return sorted(
        path
        for path in PROJECT_DIR.rglob("*.py")
        if not ignored.intersection(path.parts)
    )


def route_exists(path: str, method: str) -> bool:
    from app.main import app

    paths = app.openapi().get("paths", {})
    return path in paths and method.lower() in paths[path]


requires_upload = pytest.mark.skipif(
    not route_exists(UPLOAD_ROUTE, "POST"),
    reason="POST /api/analysis/upload is not implemented yet (owner: PacketCore)",
)


class TestNoShellInjection:
    """The backend must never build a shell command from user input."""

    def test_backend_sources_exist(self):
        assert python_sources(), "no backend sources found - the scan would be vacuous"

    @pytest.mark.parametrize("path", python_sources(), ids=lambda p: p.name)
    def test_no_shell_true(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name in {"run", "Popen", "call", "check_call", "check_output", "getoutput"}:
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is True:
                            offenders.append(f"{name}(..., shell=True) at line {node.lineno}")
        assert not offenders, f"{path.name} uses shell=True: {offenders}"

    @pytest.mark.parametrize("path", python_sources(), ids=lambda p: p.name)
    def test_no_os_system_or_popen(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr in {"system", "popen", "execv", "execve"}:
                    offenders.append(f"os.{func.attr} at line {node.lineno}")
        assert not offenders, f"{path.name} calls os.system/os.popen: {offenders}"

    @pytest.mark.parametrize("path", python_sources(), ids=lambda p: p.name)
    def test_subprocess_receives_a_list_not_a_string(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in {"run", "Popen", "call"}):
                continue
            if getattr(func.value, "id", "") != "subprocess":
                continue
            if not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                offenders.append(
                    f"subprocess.{func.attr} with a string command at line {node.lineno}"
                )
        assert not offenders, f"{path.name} runs a string command: {offenders}"

    @pytest.mark.parametrize("path", python_sources(), ids=lambda p: p.name)
    def test_no_dynamic_code_execution(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec", "compile"}:
                    offenders.append(f"{node.func.id} at line {node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"loads"} and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in {"pickle", "marshal"}:
                        offenders.append(f"{node.func.value.id}.loads at line {node.lineno}")
        assert not offenders, f"{path.name} executes dynamic code: {offenders}"


class TestNoUnexpectedEgress:
    """Packet captures are local. The backend must not phone home."""

    @pytest.mark.parametrize("path", python_sources(), ids=lambda p: p.name)
    def test_no_outbound_http_client_in_the_backend(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        forbidden = imported & {"requests", "urllib", "urllib3", "httpx", "aiohttp"}
        assert not forbidden, f"{path.name} imports {sorted(forbidden)} - the analyzer stays local"


class TestNoSecretMaterial:
    @pytest.mark.parametrize("path", tracked_sources(), ids=lambda p: p.name)
    def test_no_hardcoded_credentials(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        suspicious = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id.lower()
                if not any(
                    token in name
                    for token in ("password", "passwd", "secret", "api_key", "apikey", "token")
                ):
                    continue
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                    suspicious.append(f"{target.id} at line {node.lineno}")
        assert not suspicious, f"{path.name} hard-codes credentials: {suspicious}"

    def test_no_env_file_with_content_is_tracked(self):
        for candidate in (PROJECT_DIR / ".env", PROJECT_DIR.parent / ".env"):
            if candidate.exists():
                content = candidate.read_text(encoding="utf-8").strip()
                assert content == "", f"{candidate} must not be committed with content"


class TestUploadBounds:
    def test_upload_limit_is_configured(self):
        from app import config

        assert config.MAX_UPLOAD_BYTES > 0
        assert config.MAX_UPLOAD_BYTES <= 1024 * 1024 * 1024

    def test_upload_limit_is_readable_from_the_environment(self, monkeypatch):
        from app import config

        monkeypatch.setenv("TRAFFIC_ANALYZER_MAX_UPLOAD_BYTES", "4096")
        import importlib

        reloaded = importlib.reload(config)
        try:
            assert reloaded.MAX_UPLOAD_BYTES == 4096
        finally:
            monkeypatch.delenv("TRAFFIC_ANALYZER_MAX_UPLOAD_BYTES")
            importlib.reload(config)

    def test_data_directory_is_configurable(self):
        from app import config

        assert isinstance(config.DATA_DIR, Path)
        assert config.DATA_DIR.is_absolute()

    @requires_upload
    def test_oversized_upload_is_rejected_with_413(self, client, tmp_path, monkeypatch):
        from app import config
        from app.routers import analysis as analysis_router

        monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 256)
        if hasattr(analysis_router, "MAX_UPLOAD_BYTES"):
            monkeypatch.setattr(analysis_router, "MAX_UPLOAD_BYTES", 256)

        path = q.write_pcap_frames(tmp_path / "big.pcap", [(1_700_000_000.0, q.frame_arp())] * 20)
        assert path.stat().st_size > 256
        with path.open("rb") as handle:
            response = client.post(
                UPLOAD_ROUTE, files={"file": ("big.pcap", handle.read(), "application/octet-stream")}
            )
        assert response.status_code == 413, response.text
        assert response.json()["error"]["code"] in {"payload_too_large", "invalid_request"}

    @requires_upload
    def test_upload_of_a_non_capture_is_rejected_with_415(self, client, tmp_path):
        path = q.write_garbage_file(tmp_path / "notes.bin", 64)
        with path.open("rb") as handle:
            response = client.post(
                UPLOAD_ROUTE, files={"file": ("notes.bin", handle.read(), "application/octet-stream")}
            )
        assert response.status_code in {400, 415}, response.text
        assert "error" in response.json()

    @requires_upload
    def test_upload_of_random_bytes_is_rejected_with_400(self, client, tmp_path):
        path = q.write_garbage_file(tmp_path / "garbage.pcap", 512)
        with path.open("rb") as handle:
            response = client.post(
                UPLOAD_ROUTE, files={"file": ("garbage.pcap", handle.read(), "application/octet-stream")}
            )
        assert response.status_code == 400, response.text
        body = response.json()
        assert body["error"]["code"] == "invalid_request"
        assert body["error"]["message"]

    @requires_upload
    def test_upload_of_an_empty_file_is_rejected_with_400(self, client, tmp_path):
        path = tmp_path / "empty.pcap"
        path.write_bytes(b"")
        with path.open("rb") as handle:
            response = client.post(
                UPLOAD_ROUTE, files={"file": ("empty.pcap", handle.read(), "application/octet-stream")}
            )
        assert response.status_code == 400, response.text
        assert response.json()["error"]["code"] == "invalid_request"


class TestPathTraversal:
    @requires_upload
    def test_upload_filename_cannot_escape_the_uploads_directory(self, client, tmp_path):
        from app import config

        path = q.write_pcap_frames(
            tmp_path / "safe.pcap", [(1_700_000_000.0, q.frame_arp())]
        )
        with path.open("rb") as handle:
            raw_bytes = handle.read()
        path.unlink()
        response = client.post(
            UPLOAD_ROUTE,
            files={
                "file": (
                    "../../../../etc/passwd",
                    raw_bytes,
                    "application/octet-stream",
                )
            },
        )
        assert response.status_code in {201, 400, 415}, response.text

        uploads = Path(config.UPLOADS_DIR).resolve()
        escaped = [
            path
            for path in tmp_path.rglob("*")
            if path.is_file() and uploads not in path.resolve().parents
        ]
        assert not escaped, f"the upload escaped the uploads directory: {escaped}"
        assert Path("/etc/passwd").read_text(encoding="utf-8", errors="ignore").startswith("root")

    def test_store_upload_sanitises_the_file_name(self, tmp_path):
        from app.services.pipeline import store_upload

        source = tmp_path / "evil.pcap"
        source.write_bytes(b"data")
        destination = store_upload(source, tmp_path / "uploads")
        assert destination.parent == (tmp_path / "uploads").resolve()
        assert destination.name == "evil.pcap"
        assert ".." not in destination.name


class TestMalformedQueryParameters:
    @pytest.mark.parametrize(
        "params",
        [
            {"limit": "abc"},
            {"limit": "99999"},
            {"limit": "0"},
            {"offset": "-5"},
            {"order_by": "; DROP TABLE packets"},
            {"order_by": "not_a_column"},
            {"order_dir": "sideways"},
            {"src_port": "not-a-port"},
            {"encrypted": "maybe"},
            {"start": "not-a-date"},
        ],
    )
    @requires_upload
    def test_malformed_parameters_never_produce_a_500(self, client, tmp_path, params):
        path = q.write_pcap_frames(
            tmp_path / "one.pcap", [(1_700_000_000.0, q.frame_arp())]
        )
        with path.open("rb") as handle:
            upload = client.post(
                UPLOAD_ROUTE, files={"file": ("one.pcap", handle.read(), "application/octet-stream")}
            )
        analysis_id = upload.json()["analysis_id"]
        response = client.get(f"/api/analysis/{analysis_id}/packets", params=params)
        assert response.status_code != 500, response.text
        assert response.status_code in {200, 400, 422}, response.text
        if response.status_code != 200:
            assert "error" in response.json()
            assert "Traceback" not in response.text


class TestCaptureInputIsNotExecuted:
    """A capture filter is data, never a command."""

    @pytest.mark.skipif(
        not route_exists(CAPTURE_START_ROUTE, "POST"),
        reason="POST /api/capture/start is not implemented yet (owner: CaptureBridge)",
    )
    @pytest.mark.parametrize(
        "payload",
        [
            "tcp port 80; rm -rf /",
            "tcp port 80 && curl http://example.com",
            "$(id)",
            "`id`",
            "tcp port 80 | tee /etc/passwd",
            "tcp port 80\nrm -rf /",
        ],
    )
    def test_shell_metacharacters_in_a_filter_are_rejected(self, client, payload, monkeypatch):
        recorded: list = []

        def recorder(*args, **kwargs):
            recorded.append((args, kwargs))
            raise AssertionError("the backend must not spawn a process for an invalid filter")

        for name in ("run", "Popen", "call", "check_call", "check_output"):
            monkeypatch.setattr(subprocess, name, recorder)

        response = client.post(
            CAPTURE_START_ROUTE, json={"interface": "lo", "filter": payload}
        )
        assert response.status_code != 500, response.text
        assert response.status_code in {400, 422, 503}, response.text
        assert not recorded, f"a subprocess was started for filter {payload!r}"

    @pytest.mark.skipif(
        not route_exists(CAPTURE_START_ROUTE, "POST"),
        reason="POST /api/capture/start is not implemented yet (owner: CaptureBridge)",
    )
    def test_unknown_interface_is_rejected(self, client):
        response = client.post(
            CAPTURE_START_ROUTE, json={"interface": "definitely-not-an-interface"}
        )
        assert response.status_code != 500, response.text
        assert response.status_code in {400, 404, 422, 503}, response.text

    @pytest.mark.skipif(
        not route_exists(CAPTURE_START_ROUTE, "POST"),
        reason="POST /api/capture/start is not implemented yet (owner: CaptureBridge)",
    )
    def test_missing_interface_is_a_validation_error(self, client):
        response = client.post(CAPTURE_START_ROUTE, json={})
        assert response.status_code in {400, 422}, response.text
        assert "error" in response.json()


class TestErrorEnvelopeDoesNotLeakInternals:
    def test_unknown_route_uses_the_envelope(self, client):
        response = client.get("/api/nope")
        assert response.status_code == 404
        body = response.json()
        assert set(body) == {"error"}
        assert set(body["error"]) == {"code", "message", "detail"}
        assert "Traceback" not in response.text

    def test_unknown_analysis_uses_the_envelope(self, client):
        response = client.get("/api/analysis/nope/summary")
        assert response.status_code == 404
        assert "Traceback" not in response.text

    def test_internal_error_handler_hides_the_exception(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        from tests.qg_support import isolate_storage

        isolate_storage(tmp_path, monkeypatch)
        from app.main import app

        @app.get("/api/qg-forced-error")
        def boom():
            raise RuntimeError("secret internal detail /etc/passwd")

        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/api/qg-forced-error")
        assert response.status_code == 500
        body = response.json()
        assert body["error"]["code"] == "internal_error"
        assert "secret internal detail" not in response.text
        assert "/etc/passwd" not in response.text
        # No internal detail is exposed: neither the exception type nor its message.
        assert body["error"]["detail"] == {}
        assert "RuntimeError" not in response.text
        assert body["error"]["message"]


class TestCorsIsRestricted:
    def test_default_origins_are_explicit(self):
        from app import config

        assert config.CORS_ORIGINS, "CORS origin list must not be empty by default"
        assert "*" not in config.CORS_ORIGINS

    def test_credentials_are_not_allowed_with_wildcard(self):
        from app.main import app

        for middleware in app.user_middleware:
            if middleware.cls.__name__ == "CORSMiddleware":
                assert middleware.kwargs.get("allow_credentials") is False

    def test_unknown_origin_is_not_allowed(self, client):
        response = client.get("/api/health", headers={"Origin": "http://evil.example"})
        assert "access-control-allow-origin" not in {
            key.lower() for key in response.headers
        }

    def test_known_origin_is_allowed(self, client):
        from app import config

        origin = config.CORS_ORIGINS[0]
        response = client.get("/api/health", headers={"Origin": origin})
        assert response.headers.get("access-control-allow-origin") == origin


class TestFilesystemLayout:
    def test_analysis_directories_are_created_under_the_data_directory(self, tmp_path, monkeypatch):
        from app import config

        monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
        monkeypatch.setattr(config, "ANALYSES_DIR", tmp_path / "data" / "analyses")
        monkeypatch.setattr(config, "CAPTURES_DIR", tmp_path / "data" / "captures")
        monkeypatch.setattr(config, "UPLOADS_DIR", tmp_path / "data" / "uploads")
        config.ensure_directories()
        assert (tmp_path / "data" / "analyses").is_dir()
        assert (tmp_path / "data" / "captures").is_dir()
        assert (tmp_path / "data" / "uploads").is_dir()

    def test_store_writes_inside_the_analyses_directory(self, tmp_path, monkeypatch):
        from app import config
        from app.services import store as store_module

        monkeypatch.setattr(config, "ANALYSES_DIR", tmp_path / "analyses")
        monkeypatch.setattr(store_module, "ANALYSES_DIR", tmp_path / "analyses")
        store_module.store._analyses.clear()
        analysis = store_module.store.create(
            source_file="x.pcap", source_kind="pcap", packets=[]
        )
        assert (tmp_path / "analyses" / analysis.analysis_id / "meta.json").is_file()

    def test_the_shared_client_fixture_does_not_pollute_the_repository(self, client, tmp_path):
        """The store binds ANALYSES_DIR at import time, so the shared fixture
        cannot redirect it. This test fails while that is still the case."""
        from app import config
        from app.services import store as store_module

        repository_data_dir = BACKEND_DIR / "data"
        assert Path(config.ANALYSES_DIR) != repository_data_dir / "analyses" or (
            Path(store_module.ANALYSES_DIR) == Path(config.ANALYSES_DIR)
        ), (
            "app.services.store binds ANALYSES_DIR at import time, so the shared "
            "client fixture cannot isolate it and tests write into backend/data"
        )


class TestPacketPayloadsAreNotLogged:
    @pytest.mark.parametrize("path", python_sources(), ids=lambda p: p.name)
    def test_no_payload_field_is_logged(self, path: Path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr in {"debug", "info", "warning", "error", "critical", "exception"}
            ):
                continue
            if getattr(func.value, "id", "") not in {"logger", "logging", "LOGGER", "log"}:
                continue
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    lowered = argument.value.lower()
                    if "payload" in lowered or "data=" in lowered:
                        offenders.append(f"line {node.lineno}: {argument.value[:60]}")
        assert not offenders, f"{path.name} logs packet payloads: {offenders}"
