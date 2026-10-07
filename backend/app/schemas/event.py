from pydantic import BaseModel, Field
from typing import List, Optional, Union
from datetime import datetime

class ProcessSchema(BaseModel):
    pid: int
    name: Optional[str] = None
    username: Optional[str] = None
    exe: Optional[str] = None
    # Cmdline can be a string or list of strings depending on psutil
    cmdline: Optional[Union[str, List[str]]] = None
    cpu_percent: Optional[float] = 0.0

class AgentEventPayload(BaseModel):
    agent_id: str
    timestamp: datetime
    process: ProcessSchema
    detections: List[str] = []

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "endpoint-01",
                "timestamp": "2026-10-02T14:42:10Z",
                "process": {
                    "pid": 17012,
                    "name": "cmd.exe",
                    "username": "DELL\\User",
                    "exe": "C:\\WINDOWS\\system32\\cmd.exe",
                    "cmdline": ["C:\\WINDOWS\\system32\\cmd.exe", "/c", "test.bat"],
                    "cpu_percent": 0.0
                },
                "detections": ["Suspicious command line pattern detected"]
            }
        }
