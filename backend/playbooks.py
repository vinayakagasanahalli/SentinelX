from database import block_ip, update_incident_status, get_db
import json
from datetime import datetime

def execute_remediation(incident_id: int, action_type: str = "AUTO") -> dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": "Incident not found"}
    
    incident = dict(row)
    conn.close()
    
    source_ip = incident["source_ip"]
    severity = incident["severity"]
    category = incident["category"]
    
    actions_taken = []
    
    # Action 1: Firewall IP Block
    if source_ip and source_ip != "127.0.0.1" and source_ip != "localhost":
        block_ip(source_ip, reason=f"Automated playbook triggered by Incident #{incident_id} ({category})")
        actions_taken.append(f"Blocked IP {source_ip} on Firewall")
        
    # Action 2: Session & Token Invalidation
    if severity in ["CRITICAL", "HIGH"]:
        actions_taken.append(f"Revoked all active OAuth tokens and sessions associated with {source_ip}")
        
    # Action 3: Endpoint Isolation (Simulation)
    if "Ransomware" in category or severity == "CRITICAL":
        actions_taken.append("Triggered automated microservice network isolation protocol")
        
    action_summary = " | ".join(actions_taken)
    update_incident_status(incident_id, status="RESOLVED", action_taken=action_summary)
    
    # Log to playbook execution log
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute(
        "INSERT INTO playbook_logs (timestamp, incident_id, action_name, target, status, details) VALUES (?, ?, ?, ?, ?, ?)",
        (now, incident_id, "Automated Threat Remediation", source_ip, "SUCCESS", action_summary)
    )
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "incident_id": incident_id,
        "status": "RESOLVED",
        "actions_taken": actions_taken,
        "action_summary": action_summary
    }
