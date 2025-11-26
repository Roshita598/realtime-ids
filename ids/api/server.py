from fastapi import FastAPI
from .endpoints import router

app = FastAPI(title="Real-Time IDS API")
app.include_router(router)

# Run with:
# uvicorn realtime_ids.api.server:app --reload