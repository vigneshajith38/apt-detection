from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from app.database.connection import Base
import datetime

class AgentEvent(Base):
    __tablename__ = "agent_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Process details
    pid = Column(Integer)
    process_name = Column(String, index=True)
    username = Column(String)
    exe_path = Column(String)
    cmdline = Column(String)
    cpu_percent = Column(Float)
    
    # JSON array of strings for flags/detections from the agent
    agent_detections = Column(JSON, default=list)
