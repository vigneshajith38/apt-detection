from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.schemas.event import AgentEventPayload
from app.models.event import AgentEvent
from app.database.connection import get_db
from app.services.detection_service import evaluate_event

router = APIRouter()

@router.post("/", status_code=201)
def receive_event(payload: AgentEventPayload, db: Session = Depends(get_db)):
    """
    Ingest a security event from the endpoint agent.
    """
    # Normalize command line to a string if it's a list
    cmd_str = payload.process.cmdline
    if isinstance(cmd_str, list):
        cmd_str = " ".join(cmd_str)

    # Create the database record
    db_event = AgentEvent(
        agent_id=payload.agent_id,
        timestamp=payload.timestamp,
        pid=payload.process.pid,
        process_name=payload.process.name,
        username=payload.process.username,
        exe_path=payload.process.exe,
        cmdline=cmd_str,
        cpu_percent=payload.process.cpu_percent,
        agent_detections=payload.detections
    )
    
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    # Evaluate for alerts and map to MITRE ATT&CK
    alerts = evaluate_event(db, db_event)
    
    return {
        "status": "success", 
        "event_id": db_event.id, 
        "message": f"Event stored successfully. Generated {len(alerts)} alerts."
    }
