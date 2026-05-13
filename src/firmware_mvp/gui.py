from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
import json
import os
import subprocess
import sys
import threading
import uuid

from . import __version__


ALLOWED_COMMANDS = {
    "analyze",
    "extract",
    "infer",
    "emulate",
    "loop",
    "report",
    "feedback",
    "validate",
    "init-sample",
    "ingest-pdf",
}
ARTIFACT_NAMES = {
    "context": "context.json",
    "inference": "inference.json",
    "emulator_config": "emulator_config.json",
    "emulation_result": "emulation_result.json",
    "loop_summary": "loop_summary.json",
    "report": "report.md",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class GuiJob:
    id: str
    argv: list[str]
    cwd: Path
    status: str = "queued"
    returncode: int | None = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    logs: list[str] = field(default_factory=list)
    error: str | None = None
    process: subprocess.Popen[str] | None = field(default=None, repr=False)


class JobManager:
    def __init__(self, cwd: Path | None = None) -> None:
        self.cwd = cwd or Path.cwd()
        self._jobs: dict[str, GuiJob] = {}
        self._lock = threading.Lock()

    def start(self, argv: list[str]) -> GuiJob:
        _validate_argv(argv)
        job = GuiJob(id=uuid.uuid4().hex, argv=list(argv), cwd=self.cwd)
        with self._lock:
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def get(self, job_id: str) -> GuiJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def retry(self, job_id: str) -> GuiJob | None:
        job = self.get(job_id)
        return self.start(job.argv) if job else None

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job or not job.process or job.status not in {"queued", "running"}:
            return False
        job.process.terminate()
        job.status = "cancelled"
        job.updated_at = _now()
        return True

    def _run(self, job: GuiJob) -> None:
        command = [sys.executable, "-m", "firmware_mvp.cli", *job.argv]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.cwd / "src") + os.pathsep + env.get("PYTHONPATH", "")
        job.status = "running"
        job.updated_at = _now()
        try:
            process = subprocess.Popen(
                command,
                cwd=job.cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            job.process = process
            assert process.stdout is not None
            for line in process.stdout:
                job.logs.append(line.rstrip())
            job.returncode = process.wait()
            if job.status != "cancelled":
                _rewrite_report_with_gui_command(job)
                job.status = "completed" if job.returncode == 0 else "failed"
        except Exception as exc:  # pragma: no cover - defensive server boundary
            job.status = "failed"
            job.error = str(exc)
        finally:
            job.updated_at = _now()


def serve_gui(host: str = "127.0.0.1", port: int = 8765, cwd: Path | None = None) -> None:
    manager = JobManager(cwd)

    class Handler(FirmwareGuiHandler):
        job_manager = manager

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"firmware-mvp GUI listening on http://{host}:{server.server_port}")
    server.serve_forever()


class FirmwareGuiHandler(BaseHTTPRequestHandler):
    job_manager: JobManager

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(render_index())
            return
        if parsed.path == "/api/artifact":
            self._send_json(read_artifact(parse_qs(parsed.query)))
            return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            job = self.job_manager.get(job_id)
            self._send_json(_job_payload(job) if job else {"error": "job not found"}, 404 if not job else 200)
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        payload = self._read_json()
        parsed = urlparse(self.path)
        if parsed.path == "/api/jobs":
            job = self.job_manager.start(list(payload.get("argv", [])))
            self._send_json(_job_payload(job), 201)
            return
        if parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/cancel"):
            job_id = parsed.path.split("/")[-2]
            self._send_json({"cancelled": self.job_manager.cancel(job_id)})
            return
        if parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/retry"):
            job_id = parsed.path.split("/")[-2]
            job = self.job_manager.retry(job_id)
            self._send_json(_job_payload(job) if job else {"error": "job not found"}, 404 if not job else 201)
            return
        self._send_json({"error": "not found"}, 404)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_html(self, body: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))


def read_artifact(query: dict[str, list[str]]) -> dict[str, Any]:
    run_dir = Path(query.get("run_dir", [""])[0])
    name = query.get("name", [""])[0]
    filename = ARTIFACT_NAMES.get(name, name)
    if not run_dir or "/" in filename or filename.startswith("."):
        return {"error": "invalid artifact request"}
    path = run_dir / filename
    if not path.exists():
        return {"error": f"artifact not found: {path}"}
    return {"path": str(path), "content": path.read_text(encoding="utf-8", errors="ignore")}


def render_index() -> str:
    commands = ", ".join(sorted(ALLOWED_COMMANDS))
    artifacts = ", ".join(ARTIFACT_NAMES)
    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>Firmware MVP GUI</title>
  <style>
    body {{ font-family: sans-serif; max-width: 1100px; margin: 2rem auto; }}
    fieldset {{ margin: 1rem 0; padding: 1rem; }}
    label {{ display: block; margin: .4rem 0; }}
    input, select {{ min-width: 28rem; }}
    code, pre {{ background: #f4f4f4; padding: .2rem .4rem; }}
  </style>
</head>
<body>
  <h1>Firmware MVP GUI</h1>
  <p>Version <code>{__version__}</code>. 지원 명령: {commands}.</p>
  <fieldset>
    <legend>실행 파라미터</legend>
    <label>Command <select id="command">{_command_options()}</select></label>
    <label>Firmware / JSON / PDF path <input id="inputPath" placeholder="samples/demo_firmware.bin"></label>
    <label>Device <input id="device" value="stm32f1"></label>
    <label>Output directory <input id="out" value="runs/gui-demo"></label>
    <label>Backend <select id="backend"><option>stub</option><option>qiling</option></select></label>
    <label>Analysis backend <select id="analysisBackend"><option>heuristic</option><option>ghidra</option><option>ida</option></select></label>
    <label>Probe address <input id="probeAddress" placeholder="0x40011000"></label>
    <label>Loop max iterations <input id="maxIterations" value="3"></label>
    <label>Timeout seconds <input id="timeout" value="30"></label>
    <label>Success criterion <input id="successCriterion" placeholder="uart-output"></label>
    <button onclick="startJob()">Run / Re-run</button>
  </fieldset>
  <fieldset>
    <legend>Feedback / Validate / Artifacts</legend>
    <p>feedback 명령은 command=feedback, path=MMIO address, validate는 command=validate, path=run dir.</p>
    <p>조회 가능 산출물: {artifacts}</p>
    <label>Artifact run dir <input id="artifactRun" value="runs/gui-demo"></label>
    <label>Artifact name <input id="artifactName" value="report"></label>
    <button onclick="loadArtifact()">Open artifact</button>
  </fieldset>
  <h2>작업 상태 / 로그</h2>
  <pre id="output">대기 중</pre>
  <script>
    function argvFromForm() {{
      const c = command.value; const input = inputPath.value; const args = [c];
      if (input) args.push(input);
      if (device.value && ['analyze','run','infer','ingest-pdf'].includes(c)) args.push('--device', device.value);
      if (out.value && !['feedback','validate'].includes(c)) args.push('--out', out.value);
      if (backend.value && ['run','emulate','loop'].includes(c)) args.push('--backend', backend.value);
      if (analysisBackend.value && ['analyze','run','extract'].includes(c)) args.push('--analysis-backend', analysisBackend.value);
      if (probeAddress.value && ['run','emulate','loop'].includes(c)) args.push('--probe-address', probeAddress.value);
      if (maxIterations.value && c === 'loop') args.push('--max-iterations', maxIterations.value);
      if (timeout.value && ['run','emulate','loop'].includes(c)) args.push('--timeout-seconds', timeout.value);
      if (successCriterion.value && ['run','emulate'].includes(c)) args.push('--success-criterion', successCriterion.value);
      return args;
    }}
    async function startJob() {{
      const res = await fetch('/api/jobs', {{method:'POST', body: JSON.stringify({{argv: argvFromForm()}})}});
      const job = await res.json(); output.textContent = JSON.stringify(job, null, 2);
      poll(job.id);
    }}
    async function poll(id) {{
      const res = await fetch('/api/jobs/' + id); const job = await res.json();
      output.textContent = JSON.stringify(job, null, 2);
      if (['queued','running'].includes(job.status)) setTimeout(() => poll(id), 1000);
    }}
    async function loadArtifact() {{
      const url = `/api/artifact?run_dir=${{encodeURIComponent(artifactRun.value)}}&name=${{encodeURIComponent(artifactName.value)}}`;
      const res = await fetch(url); output.textContent = JSON.stringify(await res.json(), null, 2);
    }}
  </script>
</body>
</html>"""


def _validate_argv(argv: list[str]) -> None:
    if not argv or argv[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"unsupported GUI command: {argv[0] if argv else '<empty>'}")


def _job_payload(job: GuiJob | None) -> dict[str, Any]:
    if job is None:
        return {"error": "job not found"}
    return {
        "id": job.id,
        "argv": job.argv,
        "status": job.status,
        "returncode": job.returncode,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "logs": job.logs[-200:],
        "error": job.error,
    }


def _rewrite_report_with_gui_command(job: GuiJob) -> None:
    out_dir = _out_dir_from_argv(job.argv)
    if job.returncode != 0 or out_dir is None or not (out_dir / "report.md").exists():
        return
    command = "firmware-mvp " + " ".join(job.argv)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(job.cwd / "src") + os.pathsep + env.get("PYTHONPATH", "")
    subprocess.run(
        [sys.executable, "-m", "firmware_mvp.cli", "report", str(out_dir), "--source-command", command],
        cwd=job.cwd,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )


def _out_dir_from_argv(argv: list[str]) -> Path | None:
    for index, item in enumerate(argv):
        if item == "--out" and index + 1 < len(argv):
            return Path(argv[index + 1])
        if item.startswith("--out="):
            return Path(item.split("=", 1)[1])
    return None


def _command_options() -> str:
    return "".join(f'<option value="{command}">{command}</option>' for command in sorted(ALLOWED_COMMANDS))
