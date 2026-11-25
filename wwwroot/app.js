async function loadInterfaces() {
    const res = await fetch('/api/interfaces');
    const items = await res.json();
    const sel = document.getElementById('interfaceSelect');
    sel.innerHTML = '';
    if (items.length === 0) {
        sel.innerHTML = '<option value="127.0.0.1">Loopback (127.0.0.1)</option>';
        return;
    }
    for (const ni of items) {
        const opt = document.createElement('option');
        opt.value = ni.ipAddress;
        opt.textContent = `${ni.name} (${ni.ipAddress}) — ${ni.status}`;
        sel.appendChild(opt);
    }
}

async function refreshAll() {
    const [statusRes, rulesRes, logsRes] = await Promise.all([
        fetch('/api/status'),
        fetch('/api/rules'),
        fetch('/api/logs')
    ]);
    const status = await statusRes.json();
    const rulesCfg = await rulesRes.json();
    const logs = await logsRes.json();

    const pill = document.getElementById('statusBadge');
    pill.textContent = status.isCapturing ? `Активен: ${status.activeInterface}` : 'Остановлен';
    pill.className = 'status-pill' + (status.isCapturing ? ' active' : '');
    document.getElementById('statusMsg').textContent = status.statusMessage;
    document.getElementById('defaultPolicy').value = status.defaultPolicy;

    const s = status.stats;
    document.getElementById('statTotal').textContent = s.totalPackets;
    document.getElementById('statAllow').textContent = s.allowedPackets;
    document.getElementById('statDeny').textContent = s.deniedPackets;
    document.getElementById('statFlood').textContent = s.floodBlocks;
    document.getElementById('statProto').textContent = `${s.tcpPackets} / ${s.udpPackets} / ${s.icmpPackets}`;
    document.getElementById('statConn').textContent = s.activeConnections;

    const rulesBody = document.getElementById('rulesBody');
    rulesBody.innerHTML = rulesCfg.rules.map(r => `
        <tr style="${r.enabled ? '' : 'opacity:0.45'}">
            <td>${r.priority}</td>
            <td>${escapeHtml(r.name)}</td>
            <td><span class="badge ${r.action}">${r.action}</span></td>
            <td>${r.protocol}</td>
            <td>${escapeHtml(r.sourceIp)}</td>
            <td>${escapeHtml(r.destinationIp)}</td>
            <td>${escapeHtml(r.destinationPort)}</td>
            <td>
                <button class="btn sm" onclick="toggleRule('${r.id}')">${r.enabled ? 'Выкл' : 'Вкл'}</button>
                <button class="btn sm danger" onclick="deleteRule('${r.id}')">✕</button>
            </td>
        </tr>
    `).join('');

    const logsBody = document.getElementById('logsBody');
    logsBody.innerHTML = logs.map(ev => `
        <tr>
            <td>${new Date(ev.timestamp).toISOString().slice(11, 23)}</td>
            <td><span class="badge ${ev.action}">${ev.action}</span></td>
            <td>${ev.protocol}</td>
            <td>${ev.sourceIp}:${ev.sourcePort}</td>
            <td>${ev.destinationIp}:${ev.destinationPort}</td>
            <td>${escapeHtml(ev.flags)}</td>
            <td>${escapeHtml(ev.reason)}</td>
        </tr>
    `).join('');
}

async function startCapture() {
    const ipAddress = document.getElementById('interfaceSelect').value;
    await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ipAddress })
    });
    refreshAll();
}

async function stopCapture() {
    await fetch('/api/capture/stop', { method: 'POST' });
    refreshAll();
}

async function simulate(scenario) {
    await fetch('/api/simulate/burst', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
    });
    refreshAll();
}

async function changePolicy() {
    const policy = document.getElementById('defaultPolicy').value;
    await fetch(`/api/policy/${policy}`, { method: 'POST' });
    refreshAll();
}

async function addRule(e) {
    e.preventDefault();
    const rule = {
        priority: parseInt(document.getElementById('rPriority').value || '100', 10),
        name: document.getElementById('rName').value,
        action: document.getElementById('rAction').value,
        protocol: document.getElementById('rProto').value,
        sourceIp: document.getElementById('rSrcIp').value || '*',
        destinationIp: document.getElementById('rDstIp').value || '*',
        sourcePort: '*',
        destinationPort: document.getElementById('rDstPort').value || '*',
        enabled: true
    };
    await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule)
    });
    document.getElementById('rName').value = '';
    refreshAll();
}

async function toggleRule(id) {
    await fetch(`/api/rules/${id}/toggle`, { method: 'POST' });
    refreshAll();
}

async function deleteRule(id) {
    await fetch(`/api/rules/${id}`, { method: 'DELETE' });
    refreshAll();
}

async function reloadRules() {
    await fetch('/api/rules/reload', { method: 'POST' });
    refreshAll();
}

async function testPacket(e) {
    e.preventDefault();
    const res = await fetch('/api/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            protocol: document.getElementById('tProto').value,
            sourceIp: document.getElementById('tSrcIp').value,
            destinationIp: document.getElementById('tDstIp').value,
            sourcePort: parseInt(document.getElementById('tSrcPort').value || '0', 10),
            destinationPort: parseInt(document.getElementById('tDstPort').value || '0', 10),
            syn: true,
            ack: false
        })
    });
    const ev = await res.json();
    document.getElementById('testResult').innerHTML =
        `Результат: <span class="badge ${ev.action}">${ev.action}</span> — ${escapeHtml(ev.reason)}`;
    refreshAll();
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

loadInterfaces();
refreshAll();
setInterval(refreshAll, 1500);
