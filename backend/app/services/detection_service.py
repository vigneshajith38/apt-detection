from sqlalchemy.orm import Session
from app.models.event import AgentEvent
from app.models.alert import DetectionAlert
from app.services.mitre_service import match_technique, get_mitre_mapping

def evaluate_event(db: Session, event: AgentEvent):
    """
    Evaluates an incoming event for suspicious behavior and creates alerts.
    """
    # The agent already provides some flags. We evaluate them to generate formal alerts.
    cmd_str = event.cmdline or ""
    
    alerts_created = []
    
    for flag in event.agent_detections:
        alert_name = "Generic Suspicious Activity"
        severity = "medium"
        confidence = 0.5
        mitre_id = None
        
        # Rule 1: Command Shell Execution
        if "cmd.exe /c" in flag.lower() or "cmd.exe /c" in cmd_str.lower():
            alert_name = "Suspicious Command Shell Execution"
            severity = "medium"
            confidence = 0.8
            mitre_id = match_technique(cmd_str, event.process_name)
            
        # Rule 2: Hidden PowerShell
        elif "hidden" in flag.lower() or "powershell" in flag.lower():
            alert_name = "Hidden or Suspicious PowerShell Execution"
            severity = "high"
            confidence = 0.9
            mitre_id = match_technique(cmd_str, event.process_name)
            
        # Rule 3: High CPU Usage
        elif "cpu" in flag.lower():
            alert_name = "Unusually High CPU Consumption"
            severity = "low"
            confidence = 0.6
            
        # Map MITRE tactic if a technique was matched
        mitre_tactic = None
        if mitre_id:
            mapping = get_mitre_mapping(mitre_id)
            if mapping:
                mitre_tactic = mapping["tactic"]
                
        # Create alert record
        alert = DetectionAlert(
            event_id=event.id,
            name=alert_name,
            reason=flag,
            evidence={"process_name": event.process_name, "cmdline": cmd_str, "pid": event.pid},
            severity=severity,
            confidence=confidence,
            mitre_technique_id=mitre_id,
            mitre_tactic=mitre_tactic
        )
        db.add(alert)
        alerts_created.append(alert)
        
    if alerts_created:
        db.commit()
        
    return alerts_created
