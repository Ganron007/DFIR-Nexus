"""Process recovery must fail closed when Windows cannot inspect a PID."""

from __future__ import annotations

from nexus.langgraph.pipeline_runs import _windows_process_alive, process_alive


class _ApiCall:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class _Kernel32:
    def __init__(self, *, open_error: int = 0, exit_code: int = 259, query_ok: bool = True):
        self.OpenProcess = _ApiCall(lambda *_args: 0 if open_error else 123)
        self.GetLastError = _ApiCall(lambda: open_error)

        def get_exit_code(_handle, pointer):
            if query_ok:
                pointer._obj.value = exit_code
            return int(query_ok)

        self.GetExitCodeProcess = _ApiCall(get_exit_code)
        self.CloseHandle = _ApiCall(lambda *_args: 1)


def test_windows_access_denied_is_not_mistaken_for_a_dead_process():
    assert _windows_process_alive(123, _Kernel32(open_error=5)) is True


def test_windows_invalid_parameter_is_the_only_open_failure_treated_as_dead():
    assert _windows_process_alive(123, _Kernel32(open_error=87)) is False
    assert _windows_process_alive(123, _Kernel32(open_error=6)) is True


def test_windows_exit_query_failure_is_not_mistaken_for_a_dead_process():
    assert _windows_process_alive(123, _Kernel32(query_ok=False)) is True


def test_process_liveness_fails_closed_for_invalid_pid_values():
    assert process_alive(None) is True
    assert process_alive(0) is True

