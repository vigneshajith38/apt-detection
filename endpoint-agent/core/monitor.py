import psutil
import time
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ProcessMonitor:
    def __init__(self):
        self.known_processes = set()

    def get_all_processes(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all currently running processes with their details.
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    def get_new_processes(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of new processes that have started since the last check.
        """
        current_processes = []
        new_processes = []
        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'cpu_percent']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                if pid not in self.known_processes:
                    new_processes.append(proc.info)
                current_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        self.known_processes = current_pids
        return new_processes
