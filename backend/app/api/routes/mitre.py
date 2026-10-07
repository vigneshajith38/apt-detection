from fastapi import APIRouter
from app.services.mitre_service import MITRE_MAPPING

router = APIRouter()

@router.get("/techniques")
def get_all_mitre_techniques():
    """
    Returns the supported local MITRE ATT&CK technique mapping dictionary.
    """
    return {"status": "success", "data": list(MITRE_MAPPING.values())}
