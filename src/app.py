from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import json

from main import run_correlation, get_redis_client, init_model, MODEL_PATH, COLUMNS_PATH

app = FastAPI(title="AI Threat Correlator API", version="1.0")

class CorrelationRequest(BaseModel):
    feed_path: str = os.getenv("THREAT_FEED_PATH", "data/firehol_level1.netset")
    log_path: str = os.getenv("SERVER_LOG_PATH", "data/sample_nginx.log")


@app.on_event("startup")
def startup_event():
    # Ensure model is initialized at startup
    if not init_model():
        raise RuntimeError("Failed to initialize AI model. Check model files.")


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "ai-threat-correlator"}


@app.post("/correlate")
def correlate(request: CorrelationRequest):
    try:
        result = run_correlation()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threats/latest")
def latest_threats():
    redis_client = get_redis_client()
    if not redis_client:
        raise HTTPException(status_code=503, detail="Redis connection unavailable")

    cached = redis_client.get("ai_threat_correlator:last_results")
    if not cached:
        raise HTTPException(status_code=404, detail="No cached threat results found")

    try:
        return json.loads(cached)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to decode cached threat data")
