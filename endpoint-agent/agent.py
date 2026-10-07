import time
import logging
import requests
import os
import socket
from datetime import datetime, timezone
from core.monitor import ProcessMonitor
from core.detectors import SuspiciousActivityDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EndpointAgent")

class EndpointAgent:
    def __init__(self):
        self.monitor = ProcessMonitor()
        self.detector = SuspiciousActivityDetector()
        self.backend_url = os.getenv("BACKEND_URL", "http://127.0.0.1:8000/api/v1/events")
        self.agent_id = socket.gethostname()
        logger.info(f"Endpoint Agent initialized. Backend: {self.backend_url}")

    def report_event(self, proc: dict, flags: list):
        """Send the suspicious event payload to the backend."""
        payload = {
            "agent_id": self.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process": {
                "pid": proc.get('pid', 0),
                "name": proc.get('name') or "unknown",
                "username": proc.get('username') or "unknown",
                "exe": proc.get('exe') or "",
                "cmdline": proc.get('cmdline') or [],
                "cpu_percent": proc.get('cpu_percent') or 0.0
            },
            "detections": flags
        }
        
        try:
            response = requests.post(self.backend_url, json=payload, timeout=5)
            if response.status_code == 201:
                logger.info(f"Successfully reported event to backend (ID: {response.json().get('event_id')})")
            else:
                logger.error(f"Failed to report event: {response.text}")
        except Exception as e:
            logger.error(f"Error reporting to backend: {e}")

    def run_once(self):
        """Run a single scan of all processes."""
        logger.info("Scanning all currently running processes...")
        all_processes = self.monitor.get_all_processes()
        logger.info(f"Found {len(all_processes)} running processes.")
        
        suspicious_count = 0
        for proc in all_processes:
            flags = self.detector.analyze_process(proc)
            if flags:
                suspicious_count += 1
                pid = proc.get('pid')
                name = proc.get('name')
                logger.warning(f"[!] Suspicious Activity Detected in Process: {name} (PID: {pid})")
                for flag in flags:
                    logger.warning(f"    -> {flag}")
                
                # Send to backend
                self.report_event(proc, flags)
                    
        logger.info(f"Scan complete. Found {suspicious_count} suspicious processes.")

    def start_monitoring(self, interval=5):
        """Continuously monitor for new processes."""
        logger.info(f"Starting continuous monitoring. Polling every {interval} seconds...")
        # Populate initial known processes
        self.monitor.get_all_processes()
        # Set the known processes for differential checking
        self.monitor.get_new_processes() 
        
        try:
            while True:
                new_processes = self.monitor.get_new_processes()
                if new_processes:
                    logger.info(f"Detected {len(new_processes)} new processes.")
                    
                for proc in new_processes:
                    flags = self.detector.analyze_process(proc)
                    if flags:
                        pid = proc.get('pid')
                        name = proc.get('name')
                        logger.warning(f"[!] Suspicious Activity Detected in NEW Process: {name} (PID: {pid})")
                        for flag in flags:
                            logger.warning(f"    -> {flag}")
                        
                        # Send to backend
                        self.report_event(proc, flags)
                
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Stopping Endpoint Agent.")

if __name__ == "__main__":
    agent = EndpointAgent()
    
    # Run a full scan on startup
    agent.run_once()
    
    # Start continuous monitoring
    agent.start_monitoring(interval=5)
