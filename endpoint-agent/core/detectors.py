import re
from typing import Dict, Any, List

class SuspiciousActivityDetector:
    def __init__(self):
        # Known suspicious process names
        self.suspicious_names = {'mimikatz.exe', 'nc.exe', 'netcat.exe'}
        
        # Suspicious command line patterns
        self.suspicious_cmd_patterns = [
            re.compile(r'powershell.*-enc', re.IGNORECASE),
            re.compile(r'powershell.*-nop.*-w hidden', re.IGNORECASE),
            re.compile(r'cmd\.exe /c', re.IGNORECASE),
            re.compile(r'vssadmin.*delete shadows', re.IGNORECASE),
            re.compile(r'schtasks.*/create', re.IGNORECASE),
        ]
        
        # Suspicious paths
        self.suspicious_paths = [
            r'\\AppData\\Local\\Temp\\',
            r'\\Windows\\Temp\\'
        ]

    def analyze_process(self, proc_info: Dict[str, Any]) -> List[str]:
        """
        Analyzes a single process and returns a list of suspicious flags (if any).
        """
        flags = []
        
        name = proc_info.get('name') or ""
        exe = proc_info.get('exe') or ""
        cmdline = proc_info.get('cmdline') or []
        
        # Join command line args into a single string if it's a list
        if isinstance(cmdline, list):
            cmd_str = " ".join(cmdline)
        else:
            cmd_str = str(cmdline)

        # 1. Check for suspicious names
        if name.lower() in self.suspicious_names:
            flags.append(f"Suspicious process name detected: {name}")

        # 2. Check for suspicious command line patterns
        if cmd_str:
            for pattern in self.suspicious_cmd_patterns:
                if pattern.search(cmd_str):
                    flags.append(f"Suspicious command line pattern detected: {cmd_str}")

        # 3. Check for suspicious execution paths
        if exe:
            for path in self.suspicious_paths:
                if path.lower() in exe.lower():
                    flags.append(f"Process executed from suspicious path: {exe}")
                    
        # 4. Check for unusually high CPU usage (threshold can be adjusted)
        cpu = proc_info.get('cpu_percent')
        if cpu is not None and cpu > 90.0:
            flags.append(f"Unusually high CPU usage: {cpu}%")

        return flags
