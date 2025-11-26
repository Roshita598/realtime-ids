from fastapi import APIRouter
from ..database import Database

router = APIRouter()
db = Database()

@router.get("/alerts")
def get_alerts(limit: int = 20):
    rows = db.get_recent_alerts(limit)
    return {"alerts": rows}