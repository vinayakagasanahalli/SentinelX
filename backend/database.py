import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelx.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Table for raw ingested logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        log_level TEXT NOT NULL,
        service TEXT NOT NULL,
        message TEXT NOT NULL,
        raw_payload TEXT
    )
    """)
    
    # Table for security incidents
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        raw_logs TEXT NOT NULL,
        ai_summary TEXT NOT NULL,
        risk_score REAL NOT NULL,
        recommended_action TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN',
        action_taken TEXT DEFAULT 'PENDING'
    )
    """)
    
    # Table for blocked IPs (firewall state)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        reason TEXT NOT NULL,
        blocked_at TEXT NOT NULL,
        active INTEGER DEFAULT 1
    )
    """)

    # Table for incident response playbooks execution log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS playbook_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        incident_id INTEGER NOT NULL,
        action_name TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        details TEXT
    )
    """)

    conn.commit()
    conn.close()

def save_log(source_ip: str, log_level: str, service: str, message: str, raw_payload: str = "") -> int:
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute(
        "INSERT INTO logs (timestamp, source_ip, log_level, service, message, raw_payload) VALUES (?, ?, ?, ?, ?, ?)",
        (now, source_ip, log_level, service, message, raw_payload)
    )
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def create_incident(
    title: str,
    severity: str,
    category: str,
    source_ip: str,
    raw_logs: List[str],
    ai_summary: str,
    risk_score: float,
    recommended_action: str
) -> int:
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute(
        """INSERT INTO incidents 
           (timestamp, title, severity, category, source_ip, raw_logs, ai_summary, risk_score, recommended_action, status, action_taken)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', 'PENDING')""",
        (now, title, severity.upper(), category, source_ip, json.dumps(raw_logs), ai_summary, risk_score, recommended_action)
    )
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return incident_id

def get_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["raw_logs"] = json.loads(d["raw_logs"])
        except Exception:
            d["raw_logs"] = []
        result.append(d)
    return result

def get_blocked_ips() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips WHERE active = 1 ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def block_ip(ip: str, reason: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    try:
        cursor.execute("INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, active) VALUES (?, ?, ?, 1)", (ip, reason, now))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def update_incident_status(incident_id: int, status: str, action_taken: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE incidents SET status = ?, action_taken = ? WHERE id = ?", (status, action_taken, incident_id))
    conn.commit()
    conn.close()
    return True

def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM incidents")
    total_incidents = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL' OR severity = 'HIGH'")
    high_risk_threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE active = 1")
    blocked_count = cursor.fetchone()[0]
    
    conn.close()
    return {
        "total_logs": total_logs,
        "total_incidents": total_incidents,
        "high_risk_threats": high_risk_threats,
        "blocked_ips_count": blocked_count
    }
