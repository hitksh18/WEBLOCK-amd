"""Windows Service wrapper (requires pywin32 + admin install).

Install (elevated PowerShell):
    python -m weblock_agent.service --startup auto install
    python -m weblock_agent.service start
    # with enrollment on first run:
    set WEBLOCK_ENROLL_TOKEN=wle_...; python -m weblock_agent.service start

The service runs main.run_forever(); stop requests break the loop via the
hWaitStop event. Non-Windows import is guarded so tests can import safely.
"""
import os
import sys

SERVICE_NAME = "WebLockAgent"
SERVICE_DISPLAY = "WebLock Endpoint Agent"


def _run_service():  # pragma: no cover - needs live Windows SCM
    import win32event
    import win32service
    import win32serviceutil

    from weblock_agent.config import AgentConfig
    from weblock_agent.main import build_config, run_once

    class WebLockAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._running = False
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            import logging
            logging.basicConfig(level=logging.INFO)
            server = os.environ.get("WEBLOCK_SERVER", "http://localhost:8000")
            workdir = os.environ.get("WEBLOCK_WORKDIR", AgentConfig.workdir)
            enroll = os.environ.get("WEBLOCK_ENROLL_TOKEN", "")

            class Args:
                pass
            args = Args()
            args.server, args.workdir, args.enroll = server, workdir, enroll
            args.no_verify = os.environ.get("WEBLOCK_NO_VERIFY", "") == "1"
            cfg = build_config(args)
            interval = cfg.batch_interval * 1000
            while self._running:
                try:
                    run_once(cfg)
                except Exception:
                    logging.exception("service cycle failed")
                if win32event.WaitForSingleObject(self.hWaitStop, interval) \
                        == win32event.WAIT_OBJECT_0:
                    break

    if len(sys.argv) == 1:
        servicemanager = __import__("servicemanager")
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(WebLockAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(WebLockAgentService)


if __name__ == "__main__":
    try:
        _run_service()
    except ImportError as exc:
        raise SystemExit(f"Windows service needs pywin32 on Windows: {exc}")
