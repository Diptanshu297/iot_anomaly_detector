import logging
import shutil
import signal
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class TrafficCapture:
    def __init__(self, interface, output_dir, rotation_seconds=60, bpf_filter=""):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.rotation_seconds = rotation_seconds
        self.bpf_filter = bpf_filter
        self.process = None
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if shutil.which("tshark") is None:
            raise RuntimeError("tshark not found. Install Wireshark: https://www.wireshark.org/download.html")

    def start(self, duration_seconds=None):
        if self.process is not None:
            raise RuntimeError("Capture already running.")
        output_pattern = str(self.output_dir / "capture_%Y%m%d_%H%M%S.pcap")
        cmd = ["tshark", "-i", self.interface,
               "-b", f"duration:{self.rotation_seconds}",
               "-w", output_pattern, "-n"]
        if duration_seconds:
            cmd += ["-a", f"duration:{duration_seconds}"]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        logger.info("Starting tshark: %s", " ".join(cmd))
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return self.process

    def stop(self, timeout=5.0):
        if self.process is None:
            return
        try:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        finally:
            self.process = None

    def list_captures(self):
        return list(reversed(sorted(self.output_dir.glob("capture_*.pcap"))))
