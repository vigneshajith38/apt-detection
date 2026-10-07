from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import events, health, alerts, mitre
from app.database.connection import engine, Base

# Create database tables (SQLite/PostgreSQL)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI-Based APT Detection Backend",
    description="Backend API for endpoint agent ingestion, MITRE mapping, and attack graph generation.",
    version="1.0.0"
)

# CORS middleware for future React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to the frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(health.router, prefix="/api/v1/health", tags=["Health"])
app.include_router(events.router, prefix="/api/v1/events", tags=["Events"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(mitre.router, prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
