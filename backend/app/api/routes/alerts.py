from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.database.connection import get_db
from app.models.alert import DetectionAlert
from app.schemas.alert import DetectionAlertSchema

router = APIRouter()

@router.get("/", response_model=List[DetectionAlertSchema])
def get_alerts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve all detection alerts.
    """
    alerts = db.query(DetectionAlert).offset(skip).limit(limit).all()
    return alerts

@router.get("/{alert_id}", response_model=DetectionAlertSchema)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a specific detection alert by ID.
    """
    alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
