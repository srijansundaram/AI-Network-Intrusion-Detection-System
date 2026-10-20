/* ════════════════════════════════════════════════════════════════
   config.js — SINGLE SOURCE OF TRUTH
   Everything A or B might change lives here. Edit once, reload.
   ════════════════════════════════════════════════════════════════ */
const CONFIG = {
    USE_GROUPS: true,               // true = 8 plan categories, false = raw 15 CICIDS-2017 classes
    CONFIDENCE_CALIBRATED: false,   // flip to true ONLY when A ships temperature scaling
    CRITICAL_MIN: 85,               // attack with confidence >= this -> Critical, else Warning
    CONF_HIGH: 85,                  // confidence colour bands (green / amber / red)
    CONF_MED: 60,
    MODEL_USED: 'RF + LSTM Stacking Ensemble',
    DATASET: 'CICIDS-2017',
    BUCKET_MS: 10000,               // timeline bucket size
    MAX_ALERTS: 600,                // alerts kept in memory
};

// Order = LabelEncoder order from 02_Data_Preprocessing.ipynb (index 0..14)
const CLASS_NAMES = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest', 'DoS slowloris',
    'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan', 'SSH-Patator',
    'Web Attack - Brute Force', 'Web Attack - Sql Injection', 'Web Attack - XSS'
];

// 15 -> 8 grouping (display only; no retraining needed). Same order as CLASS_NAMES.
const GROUP_OF = [
    'Benign', 'Bot', 'DDoS', 'DDoS', 'DDoS', 'DDoS', 'DoS Slowloris',
    'Brute Force', 'Heartbleed', 'Infiltration', 'Port Scan', 'Brute Force',
    'Web Attack', 'Web Attack', 'Web Attack'
];

const catName    = i => CONFIG.USE_GROUPS ? GROUP_OF[i] : CLASS_NAMES[i];
const CATEGORIES = () => [...new Set(CLASS_NAMES.map((_, i) => catName(i)))];   // Benign first
const BENIGN     = () => catName(0);

// ── Real metrics from final_technical_performance_report.md (independent test set) ──
// prec / rec / f1 are macro-averaged (0-1). acc is %. fpr is MACRO FPR over 15 classes, %.
const MODELS = [
    { key: 'rf',   name: 'Random Forest',      acc: 99.72, prec: 0.793, rec: 0.805, f1: 0.787, fpr: 0.037 },
    { key: 'lstm', name: 'LSTM',               acc: 96.74, prec: 0.496, rec: 0.736, f1: 0.560, fpr: 0.236 },
    { key: 'ens',  name: 'Ensemble (RF+LSTM)', acc: 97.67, prec: 0.621, rec: 0.772, f1: 0.642, fpr: 0.158 },
];
const MODEL_COLOR = { rf: '#E07020', lstm: '#4A9EFF', ens: '#00D084' };

// ── Real confusion matrices (rows = true class, cols = predicted), 113,229 test sequences ──
const CONFUSION = {
  rf: [
    [90911,37,0,0,96,1,0,0,0,0,47,22,0,0,2],
    [27,35,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [1,0,5117,0,0,0,0,0,0,0,0,0,0,0,0],
    [1,0,0,397,0,0,0,0,0,0,0,0,0,0,0],
    [14,0,0,0,9291,0,0,0,0,0,0,0,0,0,2],
    [1,0,0,0,0,207,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,2,206,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,290,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [1,0,0,0,0,0,0,0,0,1,0,0,0,0,0],
    [22,0,0,0,1,0,0,0,0,0,6165,0,2,0,0],
    [2,0,0,0,0,0,0,0,0,0,0,235,0,0,0],
    [2,0,0,0,0,0,0,0,0,0,0,0,43,1,10],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],
    [0,0,0,0,1,0,0,0,0,0,0,0,24,0,10]
  ],
  lstm: [
    [87565,1258,58,168,1148,107,69,186,0,5,66,244,191,0,51],
    [10,52,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [5,0,5110,0,3,0,0,0,0,0,0,0,0,0,0],
    [7,0,0,391,0,0,0,0,0,0,0,0,0,0,0],
    [14,0,1,13,9277,0,0,0,0,0,1,1,0,0,0],
    [0,0,0,1,0,205,3,0,0,0,0,0,0,0,0],
    [0,0,0,1,0,11,196,0,0,0,0,0,0,0,0],
    [1,0,0,0,0,0,0,289,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,1,0,0,0,1,0,0,0,0,0],
    [6,0,3,0,1,0,0,0,0,0,6178,2,0,0,0],
    [6,0,0,1,1,0,0,1,0,0,0,225,3,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,6,39,0,11],
    [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,1,0,0,0,0,0,0,0,27,0,7]
  ],
  ens: [
    [88558,2130,3,13,103,3,1,0,1,45,47,143,10,0,59],
    [2,60,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,5118,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,398,0,0,0,0,0,0,0,0,0,0,0],
    [4,0,0,13,9282,0,0,0,0,0,0,0,0,0,8],
    [0,0,0,0,0,208,1,0,0,0,0,0,0,0,0],
    [0,0,0,1,0,1,206,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,290,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,1,0,0,0,1,0,0,0,0,0],
    [1,0,0,0,1,0,0,0,1,0,6185,0,0,0,2],
    [0,0,0,0,0,0,0,0,0,0,0,237,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,33,0,23],
    [0,0,0,0,0,0,0,0,0,1,0,0,0,0,0],
    [0,0,0,0,1,0,0,0,0,0,0,0,14,0,20]
  ]
};

// ── Global SHAP importance (Random Forest, 500 samples). Approximate values read from
//    global_shap_feature_importance.png — replace with global_shap_feature_importance.csv. ──
const GLOBAL_SHAP = [
    ['Destination Port', 0.0152], ['Down/Up Ratio', 0.0084], ['Flow IAT Max', 0.0080],
    ['Idle Max', 0.0051], ['Bwd Packet Length Mean', 0.0048], ['Avg Fwd Segment Size', 0.0043],
    ['Fwd Packet Length Max', 0.0042], ['Fwd IAT Total', 0.0040], ['Active Mean', 0.0039],
    ['Average Packet Size', 0.0038],
];

// ── Plain-English explanation helpers (E2) ──
const PORT_NAMES = { 21: 'FTP', 22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 8080: 'HTTP-alt' };

function fmtUs(us) {   // CICFlowMeter times are in microseconds
    us = +us;
    return us >= 1e6 ? (us / 1e6).toFixed(1) + ' s' : us >= 1e3 ? (us / 1e3).toFixed(1) + ' ms' : Math.round(us) + ' µs';
}

const FEATURE_PHRASES = {
    'Destination Port':       v => `destination port ${Math.round(v)}${PORT_NAMES[Math.round(v)] ? ' (' + PORT_NAMES[Math.round(v)] + ')' : ''}`,
    'Down/Up Ratio':          v => `a download/upload ratio of ${(+v).toFixed(1)}`,
    'Flow IAT Max':           v => `a longest packet gap of ${fmtUs(v)}`,
    'Idle Max':               v => `idle periods of up to ${fmtUs(v)}`,
    'Bwd Packet Length Mean':  v => `reply packets averaging ${Math.round(v)} bytes`,
    'Avg Fwd Segment Size':   v => `outgoing segments averaging ${Math.round(v)} bytes`,
    'Fwd Packet Length Max':  v => `an outgoing packet of ${Math.round(v)} bytes`,
    'Fwd IAT Total':          v => `outgoing traffic spread over ${fmtUs(v)}`,
    'Active Mean':            v => `active bursts averaging ${fmtUs(v)}`,
    'Average Packet Size':    v => `an average packet size of ${Math.round(v)} bytes`,
    'Flow Packets/s':         v => `${Math.round(v)} packets per second`,
    'Flow Duration':          v => `a flow lasting ${fmtUs(v)}`,
    'Total Fwd Packets':      v => `${Math.round(v)} outgoing packets`,
};

const CLASS_HINTS = {
    'DDoS': 'consistent with a traffic-flood pattern',
    'DoS Slowloris': 'consistent with a slow, connection-holding attack',
    'Port Scan': 'consistent with a port-scanning pattern',
    'Brute Force': 'consistent with repeated login attempts',
    'Bot': 'consistent with periodic command-and-control traffic',
    'Web Attack': 'consistent with a malicious web request',
    'Infiltration': 'consistent with unusual internal lateral movement',
    'Heartbleed': 'consistent with a malformed TLS heartbeat exploit',
};