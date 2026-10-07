from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.connection import Base
import datetime

class DetectionAlert(Base):
    __tablename__ = "detection_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Alert Details
    name = Column(String, index=True)
    reason = Column(String)
    evidence = Column(JSON)
    severity = Column(String) # low, medium, high, critical
    confidence = Column(Float) # 0.0 to 1.0
    
    # Relationships
    event_id = Column(Integer, ForeignKey("agent_events.id"))
    agent_event = relationship("AgentEvent", backref="alerts")
    
    # MITRE ATT&CK
    mitre_technique_id = Column(String, index=True)
    mitre_tactic = Column(String)
