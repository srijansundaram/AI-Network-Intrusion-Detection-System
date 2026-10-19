const API = { BASE: 'http://localhost:8000', USE_MOCK: false };

let _timer = null, _ws = null, _seq = 0;
const rnd  = (a, b) => a + Math.random() * (b - a);
const pick = arr => arr[Math.floor(Math.random() * arr.length)];

function argmax(a) { let m = 0; for (let i = 1; i < a.length; i++) if (a[i] > a[m]) m = i; return m; }
const toVec = p => Array.isArray(p) ? p : (p ? CLASS_NAMES.map(n => p[n] || 0) : null);

/* ── Backend payload -> dashboard alert ──────────────────────────
   Expected from B (one JSON per flow):
   { id, timestamp, src_ip, dst_ip, port, latency_ms,
     probabilities:[15], rf_probabilities:[15], lstm_probabilities:[15],
     top_features:[{name, value, shap}], lime_features:[{name, weight}] }       */
function normalizeAlert(r) {
    const ens = toVec(r.probabilities || r.class_probabilities);
    const rf = toVec(r.rf_probabilities), lstm = toVec(r.lstm_probabilities);
    const cls = argmax(ens), conf = +(ens[cls] * 100).toFixed(1);

    if (r.confidence != null) {                       // validate against backend value
        const bc = r.confidence <= 1 ? r.confidence * 100 : r.confidence;
        if (Math.abs(bc - conf) > 1) console.warn('Confidence mismatch: backend', bc, 'vs displayed', conf);
    }
    const m = v => v ? { cls: argmax(v), conf: +(Math.max(...v) * 100).toFixed(1) } : null;
    return {
        id: r.id ?? ++_seq,
        ts: new Date(r.timestamp || Date.now()),
        src: r.src_ip || '—', dst: r.dst_ip || '—', port: r.port ?? r.dst_port ?? '—',
        cls, cat: catName(cls), conf,
        models: { rf: m(rf), lstm: m(lstm), ens: { cls, conf } },
        latency: r.latency_ms ?? null,
        shap: r.top_features || [], lime: r.lime_features || [],
    };
}

/* ── Mock generator (same shape as the real payload) ─────────── */
const MOCK = {
    weights: [30, 6, 8, 4, 10, 3, 4, 5, 1, 2, 10, 6, 4, 1, 3],      // per raw class
    ports: { 'Benign': [443, 53, 80, 8080], 'Bot': [8080, 443], 'DDoS': [80, 443], 'DoS Slowloris': [80],
             'Brute Force': [22, 21], 'Heartbleed': [443], 'Infiltration': [445, 4444], 'Port Scan': null,
             'Web Attack': [80, 8080] },
    feats: {
        'DDoS':         ['Destination Port', 'Flow IAT Max', 'Down/Up Ratio', 'Fwd IAT Total', 'Flow Packets/s', 'Average Packet Size'],
        'Port Scan':    ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Fwd Packet Length Max', 'Flow Packets/s', 'Average Packet Size'],
        'Brute Force':  ['Destination Port', 'Fwd IAT Total', 'Down/Up Ratio', 'Avg Fwd Segment Size', 'Flow Duration', 'Bwd Packet Length Mean'],
        'default':      ['Destination Port', 'Down/Up Ratio', 'Flow IAT Max', 'Idle Max', 'Bwd Packet Length Mean', 'Active Mean'],
    },
};

function pickClass() {
    let r = Math.random() * MOCK.weights.reduce((a, b) => a + b, 0);
    for (let i = 0; i < MOCK.weights.length; i++) { r -= MOCK.weights[i]; if (r <= 0) return i; }
    return 0;
}
function makeProbs(k, conf) {
    const n = CLASS_NAMES.length;
    const w = Array.from({ length: n }, (_, i) => i === k ? 0 : Math.random() ** 3);
    const s = w.reduce((a, b) => a + b, 0) || 1;
    return w.map((x, i) => i === k ? conf : (1 - conf) * x / s);
}
function featValue(n, port) {
    switch (n) {
        case 'Destination Port': return port;
        case 'Down/Up Ratio': return Math.round(rnd(0, 3));
        case 'Flow IAT Max': return rnd(5e4, 9e7);
        case 'Idle Max': return rnd(0, 9e7);
        case 'Fwd IAT Total': case 'Flow Duration': return rnd(1e3, 1e8);
        case 'Flow Packets/s': return rnd(1, 40000);
        case 'Total Fwd Packets': return Math.round(rnd(1, 60));
        case 'Average Packet Size': return rnd(20, 900);
        case 'Avg Fwd Segment Size': return rnd(0, 600);
        case 'Bwd Packet Length Mean': return rnd(0, 1200);
        case 'Fwd Packet Length Max': return rnd(0, 1400);
        case 'Active Mean': return rnd(0, 5e6);
        default: return rnd(0, 1000);
    }
}

function mockAlert(ts) {
    const k = pickClass(), grp = GROUP_OF[k];
    const ports = MOCK.ports[grp];
    const port = ports ? pick(ports) : Math.floor(rnd(1, 1024));

    const rf   = makeProbs(k, rnd(0.88, 0.999));
    const lk   = Math.random() < 0.82 ? k : (Math.random() < 0.6 ? 0 : pickClass());
    const lstm = makeProbs(lk, rnd(0.55, 0.97));
    let ens = rf.map((p, i) => 0.6 * p + 0.4 * lstm[i]);
    const s = ens.reduce((a, b) => a + b, 0); ens = ens.map(p => p / s);

    const names = MOCK.feats[grp] || MOCK.feats.default;
    const base = [0.10, 0.07, 0.045, 0.03, -0.012, -0.02];
    const shap = names.map((n, i) => ({ name: n, value: featValue(n, port), shap: base[i] * rnd(0.8, 1.2) }));

    const lime = shap.map(f => ({ name: f.name, weight: f.shap * rnd(0.5, 1.5) }));
    if (Math.random() < 0.5) { const t = lime[1]; lime[1] = lime[2]; lime[2] = t; }
    if (Math.random() < 0.6) lime[3] = { name: pick(['Flow Duration', 'Total Fwd Packets', 'Active Mean', 'Fwd IAT Min']), weight: lime[3].weight };

    return {
        id: ++_seq, timestamp: ts.toISOString(),
        src_ip: pick(['203.0.113.', '198.51.100.', '192.168.1.', '172.16.0.', '10.0.0.']) + Math.floor(rnd(2, 250)),
        dst_ip: '10.0.0.' + Math.floor(rnd(1, 20)), port,
        latency_ms: rnd(5, 12),
        probabilities: ens, rf_probabilities: rf, lstm_probabilities: lstm,
        top_features: shap, lime_features: lime,
    };
}

/* ── Streams ─────────────────────────────────────────────────── */
function stopAlertStream() {
    clearInterval(_timer); _timer = null;
    if (_ws) { _ws.onclose = null; _ws.close(); _ws = null; }
}

function seedHistory(onAlert, n = 24) {          // mock only: pre-fill ~18 min of history
    const now = Date.now();
    for (let i = n; i > 0; i--) onAlert(normalizeAlert(mockAlert(new Date(now - i * 45000 - Math.random() * 20000))));
}

function startAlertStream(onAlert, onStatus, liveMock) {
    stopAlertStream();
    if (API.USE_MOCK) {
        onStatus && onStatus('mock');
        if (liveMock) _timer = setInterval(() => onAlert(normalizeAlert(mockAlert(new Date()))), 2000);
        return;
    }
    _ws = new WebSocket(API.BASE.replace(/^http/, 'ws') + '/ws/alerts');
    _ws.onopen    = () => onStatus && onStatus('live');
    _ws.onclose   = () => onStatus && onStatus('closed');
    _ws.onmessage = e => {
        const m = JSON.parse(e.data);
        if (m.type && m.type !== 'alert') return;      // ignore metrics snapshots
        onAlert(normalizeAlert(m.data || m));
    };
}

async function uploadPcap(file, onAlert, onProgress) {
    if (API.USE_MOCK) {                              // simulate a PCAP analysis burst
        const total = 40; let i = 0;
        return new Promise(res => {
            _timer = setInterval(() => {
                onAlert(normalizeAlert(mockAlert(new Date())));
                onProgress && onProgress(++i, total);
                if (i >= total) { clearInterval(_timer); res(); }
            }, 150);
        });
    }
    const fd = new FormData(); fd.append('file', file);
    const r = await fetch(API.BASE + '/api/upload', { method: 'POST', body: fd });
    if (!r.ok) throw new Error('Upload failed: ' + r.status);
    return r.json();                                  // alerts then arrive over the WebSocket
}