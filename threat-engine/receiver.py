# receiver.py - primeste evenimentele de la agentul Go, le salveaza in JSONL,
# evalueaza alertele in timp real si ofera un dashboard web modern de vizualizare.

import json
import os
import threading

from flask import Flask, jsonify, render_template_string, request
from filters import check_event, is_internal, build_alert, BruteForceTracker

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.environ.get("EVENTS_FILE", "received_events.jsonl")
ALERTS_FILE = os.environ.get("ALERTS_FILE", os.path.join(BASE_DIR, "alerts.jsonl"))
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))
INCLUDE_INTERNAL = os.environ.get("INCLUDE_INTERNAL", "true").lower() == "true"

write_lock = threading.Lock()
tracker = BruteForceTracker()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot SOC — Threat Monitor</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-main: #070b14;
            --bg-card: #0f1626;
            --bg-card-hover: #141d33;
            --bg-input: #0a0f1c;
            --border: #1e293b;
            --border-light: #2d3b55;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #06b6d4;
        }

        * { box-sizing: border-box; }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-main);
            background-image:
                radial-gradient(circle at 15% 15%, rgba(6, 182, 212, 0.06) 0%, transparent 40%),
                radial-gradient(circle at 85% 20%, rgba(239, 68, 68, 0.05) 0%, transparent 40%);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px 28px 48px;
        }

        /* Header */
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            padding-bottom: 20px;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            width: 42px;
            height: 42px;
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(59, 130, 246, 0.2));
            border: 1px solid rgba(6, 182, 212, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.15);
        }

        .brand h1 {
            margin: 0;
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: #fff;
        }

        .brand p {
            margin: 2px 0 0;
            font-size: 12px;
            color: var(--text-secondary);
        }

        .controls {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .live-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #34d399;
            cursor: pointer;
            transition: all 0.2s;
        }

        .live-badge.paused {
            background: rgba(148, 163, 184, 0.1);
            border-color: rgba(148, 163, 184, 0.3);
            color: var(--text-secondary);
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
            animation: pulse 2s infinite;
        }

        .live-badge.paused .pulse-dot {
            background: #64748b;
            box-shadow: none;
            animation: none;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .btn {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            color: var(--text-primary);
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }

        .btn:hover {
            background: var(--bg-card-hover);
            border-color: var(--accent-cyan);
        }

        /* KPI Grid */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 20px;
        }

        @media (max-width: 1024px) {
            .kpi-grid { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 560px) {
            .kpi-grid { grid-template-columns: 1fr; }
        }

        .kpi-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.15s, border-color 0.2s;
        }

        .kpi-card:hover {
            border-color: var(--border-light);
            transform: translateY(-1px);
        }

        .kpi-card::before {
            content: "";
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: var(--card-accent, var(--accent-cyan));
            opacity: 0.8;
        }

        .kpi-label {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .kpi-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 30px;
            font-weight: 700;
            color: #fff;
            line-height: 1.1;
        }

        .kpi-sub {
            margin-top: 6px;
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Analytics Section */
        .analytics-grid {
            display: grid;
            grid-template-columns: 1.1fr 0.9fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }

        @media (max-width: 1100px) {
            .analytics-grid { grid-template-columns: 1fr; }
        }

        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 20px;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }

        .panel-title {
            margin: 0;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .chart-box {
            position: relative;
            height: 210px;
            width: 100%;
        }

        /* Top Attackers List */
        .ip-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .ip-item {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .ip-row {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
        }

        .ip-addr {
            font-family: 'JetBrains Mono', monospace;
            color: #e2e8f0;
            font-weight: 500;
        }

        .ip-count {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-cyan);
            font-size: 12px;
        }

        .bar-track {
            width: 100%;
            height: 6px;
            background: #1e293b;
            border-radius: 999px;
            overflow: hidden;
        }

        .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan));
            border-radius: 999px;
            transition: width 0.4s ease;
        }

        /* Table Section */
        .table-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
        }

        .filter-pills {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .pill {
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 5px 11px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }

        .pill:hover {
            border-color: var(--border-light);
            color: #fff;
        }

        .pill.active {
            background: rgba(6, 182, 212, 0.15);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }

        .search-input {
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 7px 12px;
            border-radius: 8px;
            font-size: 13px;
            width: 260px;
            outline: none;
            transition: border-color 0.2s;
        }

        .search-input:focus {
            border-color: var(--accent-cyan);
        }

        .table-wrap {
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid var(--border);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background: #0a0f1c;
            color: var(--text-secondary);
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 11px 14px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            vertical-align: middle;
        }

        tbody tr {
            transition: background 0.12s;
        }

        tbody tr:hover {
            background: var(--bg-card-hover);
        }

        tbody tr:last-child td {
            border-bottom: none;
        }

        .mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
        }

        .badge-sev {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 5px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.03em;
        }

        .sev-CRITICAL {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.35);
        }

        .sev-HIGH {
            background: rgba(249, 115, 22, 0.15);
            color: #fb923c;
            border: 1px solid rgba(249, 115, 22, 0.35);
        }

        .sev-MEDIUM {
            background: rgba(234, 179, 8, 0.14);
            color: #facc15;
            border: 1px solid rgba(234, 179, 8, 0.32);
        }

        .sev-LOW {
            background: rgba(6, 182, 212, 0.14);
            color: #38bdf8;
            border: 1px solid rgba(6, 182, 212, 0.32);
        }

        .badge-proto {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            background: #1e293b;
            color: #cbd5e1;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 600;
        }

        .reason-cell {
            color: #e2e8f0;
            max-width: 520px;
            word-break: break-word;
        }

        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Header -->
        <header class="topbar">
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div>
                    <h1>Honeypot Threat Monitor</h1>
                    <p>Real-Time Intrusion Detection &amp; Telemetry Engine</p>
                </div>
            </div>
            <div class="controls">
                <button id="liveToggle" class="live-badge" onclick="toggleAutoRefresh()" title="Click pentru pauză/pornire actualizare automată">
                    <span class="pulse-dot"></span>
                    <span id="liveText">LIVE · 5s</span>
                </button>
                <button class="btn" onclick="fetchAlerts()">↻ Refresh</button>
            </div>
        </header>

        <!-- KPI Cards -->
        <section class="kpi-grid">
            <div class="kpi-card" style="--card-accent: #06b6d4;">
                <div class="kpi-label">Total Alerte</div>
                <div class="kpi-value" id="kpiTotal">0</div>
                <div class="kpi-sub">Evenimente malițioase filtrate</div>
            </div>
            <div class="kpi-card" style="--card-accent: #ef4444;">
                <div class="kpi-label">Alerte Critical</div>
                <div class="kpi-value" id="kpiCritical" style="color: #f87171;">0</div>
                <div class="kpi-sub">RCE, Payload-uri &amp; Login-uri reușite</div>
            </div>
            <div class="kpi-card" style="--card-accent: #3b82f6;">
                <div class="kpi-label">IP-uri Unice Atacatoare</div>
                <div class="kpi-value" id="kpiIps">0</div>
                <div class="kpi-sub">Surse distincte detectate</div>
            </div>
            <div class="kpi-card" style="--card-accent: #f97316;">
                <div class="kpi-label">Protocol Principal Țintit</div>
                <div class="kpi-value" id="kpiTopProto">—</div>
                <div class="kpi-sub" id="kpiTopProtoSub">Nicio activitate încă</div>
            </div>
        </section>

        <!-- Charts & Top Attackers -->
        <section class="analytics-grid">
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title">Atacuri pe Protocol</h2>
                </div>
                <div class="chart-box">
                    <canvas id="protoChart"></canvas>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title">Distribuție Severitate</h2>
                </div>
                <div class="chart-box">
                    <canvas id="sevChart"></canvas>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title">Top 5 IP-uri Atacatoare</h2>
                </div>
                <div id="topIpsContainer" class="ip-list">
                    <div class="empty-state" style="padding: 20px;">Fără date</div>
                </div>
            </div>
        </section>

        <!-- Alerts Feed Table -->
        <section class="panel">
            <div class="table-toolbar">
                <div class="filter-pills" id="sevFilters">
                    <button class="pill active" data-sev="ALL" onclick="setSeverityFilter('ALL')">TOATE</button>
                    <button class="pill" data-sev="CRITICAL" onclick="setSeverityFilter('CRITICAL')">CRITICAL</button>
                    <button class="pill" data-sev="HIGH" onclick="setSeverityFilter('HIGH')">HIGH</button>
                    <button class="pill" data-sev="MEDIUM" onclick="setSeverityFilter('MEDIUM')">MEDIUM</button>
                    <button class="pill" data-sev="LOW" onclick="setSeverityFilter('LOW')">LOW</button>
                </div>
                <input
                    type="text"
                    id="searchBox"
                    class="search-input"
                    placeholder="Caută IP, protocol, comandă..."
                    oninput="renderTable()"
                >
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp (UTC)</th>
                            <th>Severitate</th>
                            <th>IP Sursă</th>
                            <th>Protocol</th>
                            <th>Detalii Amenințare</th>
                        </tr>
                    </thead>
                    <tbody id="alertsBody"></tbody>
                </table>
            </div>
        </section>
    </div>

    <script>
        let allAlerts = {{ initial_alerts | tojson }};
        let currentSevFilter = 'ALL';
        let autoRefresh = true;
        let protoChart = null;
        let sevChart = null;

        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function initCharts() {
            const protoCtx = document.getElementById('protoChart').getContext('2d');
            protoChart = new Chart(protoCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Evenimente',
                        data: [],
                        backgroundColor: 'rgba(6, 182, 212, 0.75)',
                        borderColor: '#06b6d4',
                        borderWidth: 1,
                        borderRadius: 6,
                        maxBarThickness: 44
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(30, 41, 59, 0.7)' },
                            ticks: { color: '#94a3b8', precision: 0, font: { family: 'JetBrains Mono', size: 11 } }
                        }
                    }
                }
            });

            const sevCtx = document.getElementById('sevChart').getContext('2d');
            sevChart = new Chart(sevCtx, {
                type: 'doughnut',
                data: {
                    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#06b6d4'],
                        borderColor: '#0f1626',
                        borderWidth: 3,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '68%',
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: '#cbd5e1',
                                padding: 14,
                                usePointStyle: true,
                                pointStyle: 'circle',
                                font: { family: 'JetBrains Mono', size: 11 }
                            }
                        }
                    }
                }
            });
        }

        function updateDashboard() {
            const total = allAlerts.length;
            const protoCounts = {};
            const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
            const ipCounts = {};

            for (const a of allAlerts) {
                const proto = (a.protocol || 'UNKNOWN').toUpperCase();
                protoCounts[proto] = (protoCounts[proto] || 0) + 1;

                const sev = (a.severity || 'LOW').toUpperCase();
                if (sev in sevCounts) sevCounts[sev]++;

                const ip = a.source_ip;
                if (ip) ipCounts[ip] = (ipCounts[ip] || 0) + 1;
            }

            // Update KPIs
            document.getElementById('kpiTotal').textContent = total;
            document.getElementById('kpiCritical').textContent = sevCounts.CRITICAL;
            document.getElementById('kpiIps').textContent = Object.keys(ipCounts).length;

            const sortedProtos = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]);
            if (sortedProtos.length > 0) {
                document.getElementById('kpiTopProto').textContent = sortedProtos[0][0];
                document.getElementById('kpiTopProtoSub').textContent = `${sortedProtos[0][1]} atacuri detectate`;
            } else {
                document.getElementById('kpiTopProto').textContent = '—';
                document.getElementById('kpiTopProtoSub').textContent = 'Nicio activitate încă';
            }

            // Update Charts
            protoChart.data.labels = sortedProtos.map(p => p[0]);
            protoChart.data.datasets[0].data = sortedProtos.map(p => p[1]);
            protoChart.update();

            sevChart.data.datasets[0].data = [
                sevCounts.CRITICAL,
                sevCounts.HIGH,
                sevCounts.MEDIUM,
                sevCounts.LOW
            ];
            sevChart.update();

            // Update Top 5 IPs
            const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
            const topIpsEl = document.getElementById('topIpsContainer');
            if (topIps.length === 0) {
                topIpsEl.innerHTML = '<div class="empty-state" style="padding: 30px 10px;">Niciun IP înregistrat</div>';
            } else {
                const maxHits = topIps[0][1];
                topIpsEl.innerHTML = topIps.map(([ip, count]) => {
                    const pct = Math.max(8, Math.round((count / maxHits) * 100));
                    return `
                        <div class="ip-item">
                            <div class="ip-row">
                                <span class="ip-addr">${escapeHtml(ip)}</span>
                                <span class="ip-count">${count} hit-uri</span>
                            </div>
                            <div class="bar-track">
                                <div class="bar-fill" style="width: ${pct}%"></div>
                            </div>
                        </div>
                    `;
                }).join('');
            }

            renderTable();
        }

        function setSeverityFilter(sev) {
            currentSevFilter = sev;
            document.querySelectorAll('#sevFilters .pill').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.sev === sev);
            });
            renderTable();
        }

        function renderTable() {
            const query = document.getElementById('searchBox').value.trim().toLowerCase();
            const tbody = document.getElementById('alertsBody');

            const filtered = allAlerts.slice().reverse().filter(a => {
                const sev = (a.severity || 'LOW').toUpperCase();
                if (currentSevFilter !== 'ALL' && sev !== currentSevFilter) return false;

                if (query) {
                    const hay = `${a.source_ip || ''} ${a.protocol || ''} ${a.alert_reason || ''} ${sev}`.toLowerCase();
                    if (!hay.includes(query)) return false;
                }
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" class="empty-state">
                            Nicio alertă nu corespunde filtrului curent.
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = filtered.slice(0, 100).map(a => {
                const rawTs = a.processed_at || a.timestamp || '';
                const cleanTs = rawTs.replace('T', ' ').slice(0, 19) || '—';
                const sev = (a.severity || 'LOW').toUpperCase();
                const ip = a.source_ip || 'N/A';
                const proto = (a.protocol || 'UNKNOWN').toUpperCase();
                const reason = a.alert_reason || '';

                return `
                    <tr>
                        <td class="mono" style="color: #94a3b8; white-space: nowrap;">${escapeHtml(cleanTs)}</td>
                        <td><span class="badge-sev sev-${escapeHtml(sev)}">${escapeHtml(sev)}</span></td>
                        <td class="mono" style="color: #38bdf8; white-space: nowrap;">${escapeHtml(ip)}</td>
                        <td><span class="badge-proto">${escapeHtml(proto)}</span></td>
                        <td class="reason-cell mono">${escapeHtml(reason)}</td>
                    </tr>
                `;
            }).join('');
        }

        async function fetchAlerts() {
            try {
                const res = await fetch('/api/alerts');
                if (!res.ok) return;
                const data = await res.json();
                if (Array.isArray(data.alerts)) {
                    allAlerts = data.alerts;
                    updateDashboard();
                }
            } catch (err) {
                console.error('Eroare la actualizarea alertelor:', err);
            }
        }

        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const badge = document.getElementById('liveToggle');
            const label = document.getElementById('liveText');
            badge.classList.toggle('paused', !autoRefresh);
            label.textContent = autoRefresh ? 'LIVE · 5s' : 'PAUSED';
        }

        initCharts();
        updateDashboard();
        setInterval(() => {
            if (autoRefresh) fetchAlerts();
        }, 5000);
    </script>
</body>
</html>
"""


def load_saved_alerts(limit=500):
    if not os.path.exists(ALERTS_FILE):
        return 0, []
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    alerts = []
    for line in lines[-limit:]:
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return len(lines), alerts


def append_alerts(alerts):
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")


@app.post("/api/events")
def receive_events():
    if AGENT_TOKEN and request.headers.get("Authorization") != f"Bearer {AGENT_TOKEN}":
        return jsonify(error="token gresit"), 401

    events = request.get_json(silent=True)
    if not isinstance(events, list):
        return jsonify(error="body-ul trebuie sa fie un array JSON"), 400

    good = [ev for ev in events if isinstance(ev, dict)]
    new_alerts = []

    with write_lock:
        for ev in good:
            if is_internal(ev) and not INCLUDE_INTERNAL:
                continue
            is_threat, severity, reason = check_event(ev, tracker)
            if is_threat:
                new_alerts.append(build_alert(ev, severity, reason))
                print(f"[REALTIME-ALERT][{severity}] {ev.get('source_ip', '?')} -> {reason}")

        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            for ev in good:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

        if new_alerts:
            append_alerts(new_alerts)

    print(f"[+] primit {len(good)} evenimente ({len(new_alerts)} alerte generate)")
    return jsonify(received=len(good), alerts_generated=len(new_alerts)), 200


@app.get("/api/alerts")
def get_alerts():
    total, alerts = load_saved_alerts()
    return jsonify(total=total, alerts=alerts), 200


@app.get("/")
def dashboard():
    _, alerts = load_saved_alerts()
    return render_template_string(DASHBOARD_HTML, initial_alerts=alerts)


if __name__ == "__main__":
    print(f"receiver pornit pe http://localhost:{PORT} | scriu in {EVENTS_FILE}")
    app.run(host="0.0.0.0", port=PORT)
