from fastapi.testclient import TestClient
from app.main import app
import datetime

client = TestClient(app)

def test_health_check():
    response = client.get("/api/v1/health/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "ATP Backend is running"}

def test_receive_event():
    payload = {
        "agent_id": "test-agent-01",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "process": {
            "pid": 1234,
            "name": "test_malware.exe",
            "exe": "C:\\temp\\test_malware.exe",
            "cmdline": ["test_malware.exe", "--hide"],
            "cpu_percent": 99.9
        },
        "detections": ["High CPU usage", "Suspicious path"]
    }
    
    response = client.post("/api/v1/events/", json=payload)
    assert response.status_code == 201
    assert response.json()["status"] == "success"
    assert "event_id" in response.json()
