"""Unit tests for ProcessRunner execution engine."""

import time
import threading
import pytest
from storage.models import ExecutionStatus
from terminal.runner import ProcessRunner


def test_process_runner_success_and_streaming():
    runner = ProcessRunner()
    captured_lines = []

    def on_output(line: str, stream: str):
        captured_lines.append((line.strip(), stream))

    result = runner.run(
        ["echo", "Hello Cybersecurity Platform"],
        timeout=5.0,
        on_output=on_output,
    )

    assert result.status == ExecutionStatus.COMPLETED
    assert result.exit_code == 0
    assert "Hello Cybersecurity Platform" in result.stdout
    assert len(captured_lines) >= 1
    assert captured_lines[0] == ("Hello Cybersecurity Platform", "stdout")
    assert result.duration_seconds >= 0.0


def test_process_runner_captures_stderr():
    runner = ProcessRunner()
    captured = []

    def on_output(line: str, stream: str):
        captured.append((line.strip(), stream))

    result = runner.run(
        ["python3", "-c", "import sys; sys.stderr.write('Alert: Warning emitted\\n'); sys.exit(2)"],
        timeout=5.0,
        on_output=on_output,
    )

    assert result.status == ExecutionStatus.FAILED
    assert result.exit_code == 2
    assert "Alert: Warning emitted" in result.stderr
    assert ("Alert: Warning emitted", "stderr") in captured


def test_process_runner_timeout():
    runner = ProcessRunner()

    result = runner.run(
        ["sleep", "10"],
        timeout=0.3,
    )

    assert result.status == ExecutionStatus.TIMEOUT
    assert result.exit_code == -1
    assert result.duration_seconds >= 0.25


def test_process_runner_cancellation():
    runner = ProcessRunner()

    # Start sleep in a background thread and cancel after 0.1s
    def cancel_after_delay():
        time.sleep(0.1)
        runner.cancel()

    cancel_thread = threading.Thread(target=cancel_after_delay)
    cancel_thread.start()

    result = runner.run(
        ["sleep", "5"],
        timeout=5.0,
    )
    cancel_thread.join()

    assert result.status == ExecutionStatus.CANCELLED


def test_process_runner_rejects_empty_command():
    runner = ProcessRunner()
    with pytest.raises(ValueError):
        runner.run([])


def test_process_runner_reports_missing_executable():
    runner = ProcessRunner()
    captured = []

    result = runner.run(
        ["/definitely/missing/cybersecuritysuite-tool"],
        on_output=lambda chunk, stream: captured.append((chunk, stream)),
    )

    assert result.status == ExecutionStatus.FAILED
    assert result.exit_code == 127
    assert "Unable to start" in result.stderr
    assert captured == [(result.stderr, "stderr")]


def test_process_runner_executes_bin_wrappers_with_code_zero():
    """Verify ProcessRunner executes bin/ wrappers (sqlmap, wafw00f) with exit code 0."""
    runner = ProcessRunner()
    res_sql = runner.run(["sqlmap", "--version"], timeout=5.0)
    assert res_sql.status == ExecutionStatus.COMPLETED
    assert res_sql.exit_code == 0
    assert "SyntaxError" not in res_sql.stdout
    assert "SyntaxError" not in res_sql.stderr
    assert "1.10" in res_sql.stdout

    res_waf = runner.run(["wafw00f", "--version"], timeout=5.0)
    assert res_waf.status == ExecutionStatus.COMPLETED
    assert res_waf.exit_code == 0
    assert "SyntaxError" not in res_waf.stdout
    assert "WAFW00F" in res_waf.stdout
