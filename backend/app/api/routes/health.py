from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def health_check():
    """
    Check if the backend is running.
    """
    return {"status": "ok", "message": "ATP Backend is running"}
