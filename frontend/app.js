const API_BASE = "http://localhost:8085/api/v1";
let currentIncident = null;

document.addEventListener("DOMContentLoaded", () => {
    fetchData();
    setInterval(fetchData, 4000); // Live poll every 4s
});

async function fetchData() {
    try {
        const [statsRes, incidentsRes, blockedRes] = await Promise.all([
            fetch(`${API_BASE}/stats`).then(r => r.json()),
            fetch(`${API_BASE}/incidents`).then(r => r.json()),
            fetch(`${API_BASE}/blocked-ips`).then(r => r.json())
        ]);

        updateStats(statsRes);
        renderIncidents(incidentsRes);
        renderBlockedIPs(blockedRes);
    } catch (err) {
        console.error("Failed to connect to SentinelX API:", err);
        document.getElementById("system-status").textContent = "OFFLINE (API Connecting...)";
    }
}

function updateStats(stats) {
    document.getElementById("stat-logs").textContent = stats.total_logs || 0;
    document.getElementById("stat-incidents").textContent = stats.total_incidents || 0;
    document.getElementById("stat-threats").textContent = stats.high_risk_threats || 0;
    document.getElementById("stat-blocked").textContent = stats.blocked_ips_count || 0;
    document.getElementById("system-status").textContent = "ONLINE";
}

function renderIncidents(incidents) {
    const container = document.getElementById("incidents-container");
    if (!incidents || incidents.length === 0) {
        container.innerHTML = `<div class="loading-state">No incidents detected yet. Use the Attack Simulator above to test threat detection.</div>`;
        return;
    }

    container.innerHTML = incidents.map(inc => `
        <div class="incident-item ${inc.severity}" onclick="openModal(${inc.id})">
            <div>
                <div class="incident-title">${escapeHtml(inc.title)}</div>
                <div class="incident-meta">
                    <span>IP: <code class="mono">${escapeHtml(inc.source_ip)}</code></span>
                    <span>Risk: <strong>${inc.risk_score}</strong></span>
                    <span>${new Date(inc.timestamp).toLocaleTimeString()}</span>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span class="severity-tag ${inc.severity}">${inc.severity}</span>
                <span style="font-size: 0.8rem; opacity: 0.7;">${inc.status === 'RESOLVED' ? '✅ Resolved' : '⚠️ Open'}</span>
            </div>
        </div>
    `).join("");
}

function renderBlockedIPs(blockedList) {
    const list = document.getElementById("blocked-ips-list");
    document.getElementById("blocked-badge-count").textContent = blockedList.length;

    if (!blockedList || blockedList.length === 0) {
        list.innerHTML = `<li class="empty-list">No active IP blocks recorded.</li>`;
        return;
    }

    list.innerHTML = blockedList.map(item => `
        <li class="blocked-item">
            <div class="blocked-ip">${escapeHtml(item.ip)}</div>
            <div style="color: var(--text-secondary); font-size: 0.75rem;">Reason: ${escapeHtml(item.reason)}</div>
        </li>
    `).join("");
}

async function simulateAttack(type) {
    try {
        const res = await fetch(`${API_BASE}/simulate-attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: type })
        });
        const data = await res.json();
        fetchData();
    } catch (err) {
        alert("Failed to trigger attack simulation: " + err.message);
    }
}

async function openModal(incidentId) {
    try {
        const incidents = await fetch(`${API_BASE}/incidents`).then(r => r.json());
        const inc = incidents.find(i => i.id === incidentId);
        if (!inc) return;

        currentIncident = inc;
        
        document.getElementById("modal-title").textContent = inc.title;
        document.getElementById("modal-severity-tag").textContent = inc.severity;
        document.getElementById("modal-severity-tag").className = `severity-tag ${inc.severity}`;
        document.getElementById("modal-category").textContent = inc.category;
        document.getElementById("modal-ip").textContent = inc.source_ip;
        document.getElementById("modal-risk").textContent = inc.risk_score;
        document.getElementById("modal-status").textContent = inc.status;
        
        document.getElementById("modal-ai-summary").textContent = inc.ai_summary;
        document.getElementById("modal-raw-logs").textContent = inc.raw_logs.join("\n");
        document.getElementById("modal-recommendation").textContent = inc.recommended_action;
        
        const actionTakenEl = document.getElementById("modal-action-taken");
        if (inc.action_taken && inc.action_taken !== 'PENDING') {
            actionTakenEl.innerHTML = `<strong>Action Executed:</strong> ${escapeHtml(inc.action_taken)}`;
            document.getElementById("modal-remediate-btn").style.display = "none";
        } else {
            actionTakenEl.innerHTML = "";
            document.getElementById("modal-remediate-btn").style.display = "inline-block";
        }

        document.getElementById("incident-modal").classList.add("active");
    } catch (err) {
        console.error("Error opening modal:", err);
    }
}

function closeModal() {
    document.getElementById("incident-modal").classList.remove("active");
}

async function executeManualRemediation() {
    if (!currentIncident) return;
    try {
        const res = await fetch(`${API_BASE}/incidents/${currentIncident.id}/remediate`, {
            method: "POST"
        });
        const data = await res.json();
        alert(`Playbook Action Completed!\n${data.action_summary}`);
        closeModal();
        fetchData();
    } catch (err) {
        alert("Error executing remediation: " + err.message);
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
