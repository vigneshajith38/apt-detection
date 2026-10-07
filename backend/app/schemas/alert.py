from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime

class DetectionAlertSchema(BaseModel):
    id: int
    timestamp: datetime
    name: str
    reason: str
    evidence: Dict[str, Any]
    severity: str
    confidence: float
    event_id: int
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None

    class Config:
        from_attributes = True
