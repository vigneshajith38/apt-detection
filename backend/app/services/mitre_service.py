from typing import Dict, Optional

# Structured local mapping of MITRE ATT&CK techniques
MITRE_MAPPING = {
    "T1059.003": {
        "id": "T1059.003",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution"
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution"
    },
    "T1564.003": {
        "id": "T1564.003",
        "name": "Hide Artifacts: Hidden Window",
        "tactic": "Defense Evasion"
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact"
    },
    "T1036": {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion"
    }
}

def get_mitre_mapping(technique_id: str) -> Optional[Dict]:
    """Retrieve MITRE technique details by ID."""
    return MITRE_MAPPING.get(technique_id)

def match_technique(command_line: str, process_name: str) -> Optional[str]:
    """
    Very basic heuristic to map a command line or process to a MITRE technique.
    """
    cmd = command_line.lower() if command_line else ""
    proc = process_name.lower() if process_name else ""
    
    if "powershell" in cmd or "powershell.exe" in proc:
        if "-w hidden" in cmd or "-windowstyle hidden" in cmd:
            return "T1564.003" # Hide Artifacts: Hidden Window
        return "T1059.001" # PowerShell
        
    if "cmd.exe /c" in cmd:
        return "T1059.003" # Windows Command Shell
        
    if "vssadmin" in cmd and "delete" in cmd:
        return "T1490" # Inhibit System Recovery
        
    return None
