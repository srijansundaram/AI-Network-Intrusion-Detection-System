/* ════════════════════════════════════════════════════════════════
   app.js — dashboard logic (feed, cards, timeline, models, errors,
   explainability, confidence, PDF export). Needs config.js + api.js.
   ════════════════════════════════════════════════════════════════ */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const state = {
    alerts: [], mode: 'live', minConf: 60,
    sevs: new Set(['Critical', 'Warning', 'Normal']),
    sortBy: 'time', pcapName: null,
    tlCats: new Set(CATEGORIES().filter(c => c !== BENIGN())), tlLive: true,
    mdlSel: new Set(['rf', 'lstm', 'ens']),
    errSel: new Set(['rf', 'lstm', 'ens']), errCat: 'All', errMetric: 'fp',
    exSel: 'latest',
};

/* ── Helpers ─────────────────────────────────────────────────── */
const SEV = {
    Critical: { dot: 'd-red', color: '#FF2D2D' },
    Warning:  { dot: 'd-org', color: '#FF8C42' },
    Normal:   { dot: 'd-grn', color: '#00D084' },
};
const isBenign   = cls => cls === 0;
const severityOf = (cls, conf) => isBenign(cls) ? 'Normal' : (conf >= CONFIG.CRITICAL_MIN ? 'Critical' : 'Warning');
const confColor  = c => c >= CONFIG.CONF_HIGH ? '#00D084' : c >= CONFIG.CONF_MED ? '#FF8C42' : '#FF2D2D';
const confLabel  = () => CONFIG.CONFIDENCE_CALIBRATED ? 'Calibrated confidence' : 'Model confidence (uncalibrated)';
const setText    = (sel, v) => { const e = $(sel); if (e) e.textContent = v; };
const sum        = a => a.reduce((s, v) => s + v, 0);
const fmtN       = n => Number(n).toLocaleString();
const tabActive  = name => $('#tab-' + name).classList.contains('active');

const DARK = (extra = {}) => Object.assign({
    paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)',
    font: { color: '#9B8878', size: 10, family: 'Inter' }, margin: { t: 10, b: 36, l: 44, r: 12 },
}, extra);
const GRID = 'rgba(255,255,255,0.06)';
const PCFG = { responsive: true, displayModeBar: false };

function chips(el, items, set, onChange, label = x => x) {
    el.innerHTML = '';
    items.forEach(it => {
        const b = document.createElement('button');
        b.className = 'chip' + (set.has(it) ? ' on' : ''); b.textContent = label(it);
        b.onclick = () => { set.has(it) ? set.delete(it) : set.add(it); b.classList.toggle('on'); onChange(); };
        el.appendChild(b);
    });
}

function gaugeSVG(pct, color) {
    const c = Math.PI * 34, off = c * (1 - pct / 100);
    return `<svg width="90" height="54" viewBox="0 0 90 54">
        <path d="M11 49 A34 34 0 0 1 79 49" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="8" stroke-linecap="round"/>
        <path d="M11 49 A34 34 0 0 1 79 49" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}"/>
        <text x="45" y="46" text-anchor="middle" font-size="14" font-weight="700" fill="#F0EBE5">${pct}%</text></svg>`;
}

/* ── Plain-English explanation (E2) ──────────────────────────── */
function buildSentence(a) {
    if (isBenign(a.cls)) return 'Classified as normal traffic — no attack pattern in the dominant features.';
    const parts = a.shap.filter(f => f.shap > 0).slice(0, 3)
        .map(f => FEATURE_PHRASES[f.name] ? FEATURE_PHRASES[f.name](f.value) : `${f.name} = ${(+f.value).toFixed(1)}`);
    const list = parts.length > 1 ? parts.slice(0, -1).join(', ') + ' and ' + parts[parts.length - 1]
                                  : (parts[0] || 'the combined flow statistics');
    const hint = CLASS_HINTS[GROUP_OF[a.cls]];
    return `Flagged as ${a.cat} (${a.conf}% confidence) because of ${list}${hint ? ' — ' + hint : ''}.`;
}

/* ════════════ INGEST ════════════ */
function onAlert(a) {
    a.sev = severityOf(a.cls, a.conf);
    a.sentence = buildSentence(a);
    state.alerts.push(a);
    if (state.alerts.length > CONFIG.MAX_ALERTS) state.alerts.shift();
    addFeedItem(a); updateCards(); scheduleTimeline(); updateModelsLive();
    if (tabActive('explain') && state.exSel === 'latest') renderExplain();
}

function resetAlerts() {
    state.alerts = []; renderFeed(); updateCards();
    if (tabActive('timeline')) renderTimeline();
}

/* ════════════ FEED + CONFIDENCE ════════════ */
const passes = a => a.conf >= state.minConf && state.sevs.has(a.sev);

function detailHTML(a) {
    const mbar = (key, label) => {
        const m = a.models[key]; if (!m) return '';
        const c = confColor(m.conf);
        const diff = m.cls !== a.cls ? ` <span class="warn-tag">⚠ ${catName(m.cls)}</span>` : '';
        return `<div class="mbar"><div class="mbar-top"><span>${label}${diff}</span><b style="color:${c}">${m.conf}%</b></div>
                <div class="conf-bar-track"><div class="conf-bar-fill" style="width:${m.conf}%;background:${c}"></div></div></div>`;
    };
    return `<div class="shap-box">💡 ${a.sentence}</div>
    <div class="detail-grid">
        <div>
            <div class="detail-col-title">Traffic Details</div>
            <div class="detail-row"><b>Attack Type:</b> <code>${a.cat}</code></div>
            <div class="detail-row"><b>Severity:</b> <code>${a.sev}</code></div>
            <div class="detail-row"><b>Source IP:</b> <code>${a.src}</code></div>
            <div class="detail-row"><b>Destination IP:</b> <code>${a.dst}</code></div>
            <div class="detail-row"><b>Port:</b> <code>${a.port}</code></div>
            <div class="detail-row"><b>Time:</b> <code>${a.ts.toLocaleTimeString()}</code></div>
        </div>
        <div>
            <div class="detail-col-title">${confLabel()}</div>
            <div class="gauge-row">${gaugeSVG(Math.round(a.conf), confColor(a.conf))}
                <div style="flex:1">${mbar('rf', 'Random Forest')}${mbar('lstm', 'LSTM')}${mbar('ens', 'Ensemble')}</div>
            </div>
        </div>
    </div>
    <button class="link-btn" data-explain>🧠 Compare SHAP vs LIME →</button>`;
}

function makeItem(a) {
    const el = document.createElement('div');
    el.className = 'activity-item'; el.dataset.id = a.id;
    el.innerHTML = `<div class="a-dot ${SEV[a.sev].dot}"></div>
        <div style="flex:1"><div class="a-text"><b>${a.cat}</b> — ${a.conf}% · ${a.src} → ${a.dst}:${a.port}</div>
        <div class="a-time">${a.ts.toLocaleTimeString()} · ${a.sev}</div></div>
        <span class="a-arr">›</span><div class="a-detail"></div>`;
    const d = $('.a-detail', el);
    el.addEventListener('click', () => { if (!d.innerHTML) d.innerHTML = detailHTML(a); el.classList.toggle('open'); });
    d.addEventListener('click', e => {
        e.stopPropagation();
        if (e.target.closest('[data-explain]')) { state.exSel = String(a.id); activateTab('explain'); }
    });
    return el;
}

function updateSub() {
    setText('#feed-sub', `${state.alerts.filter(passes).length} alerts shown · updated ${new Date().toLocaleTimeString()}`);
}

function renderFeed() {
    const list = $('#activity-list'); list.innerHTML = '';
    let arr = state.alerts.filter(passes);
    arr = state.sortBy === 'conf' ? [...arr].sort((x, y) => y.conf - x.conf) : [...arr].reverse();
    arr.slice(0, 150).forEach(a => list.appendChild(makeItem(a)));
    if (!arr.length) list.innerHTML = '<div class="empty">No alerts match the current filters.</div>';
    updateSub();
}

function addFeedItem(a) {
    if (!passes(a)) { updateSub(); return; }
    if (state.sortBy !== 'time') { renderFeed(); return; }
    const list = $('#activity-list'), e = $('.empty', list); if (e) e.remove();
    list.prepend(makeItem(a));
    while (list.children.length > 150) list.lastChild.remove();
    updateSub();
}

/* ════════════ TOP CARDS ════════════ */
function updateCards() {
    const A = state.alerts, now = Date.now();
    const crit = A.filter(a => a.sev === 'Critical');
    const attacks = A.filter(a => a.sev !== 'Normal');
    const threats = new Set(attacks.filter(a => now - a.ts < 300000).map(a => a.src)).size;
    const lat = A.map(a => a.latency).filter(v => v != null).sort((x, y) => x - y);
    setText('#m-critical', crit.length);
    setText('#m-critical-d', `${crit.filter(a => now - a.ts < 60000).length} in last minute`);
    setText('#m-threats', threats);
    setText('#m-flows', fmtN(A.length));
    setText('#m-flows-d', A.length ? `attack share ${Math.round(attacks.length / A.length * 100)}%` : '—');
    $('#m-latency').innerHTML = lat.length
        ? `${(sum(lat) / lat.length).toFixed(1)}<span style="font-size:12px;font-weight:400;color:var(--t2)">ms</span>` : '—';
    setText('#m-latency-d', lat.length ? `p95 ${lat[Math.floor(lat.length * 0.95)].toFixed(1)} ms` : 'per flow');
}

/* ════════════ TIMELINE (E4) ════════════ */
let _tlT = null;
function scheduleTimeline() {
    if (!state.tlLive || _tlT || !tabActive('timeline')) return;
    _tlT = setTimeout(() => { _tlT = null; renderTimeline(); }, 1500);
}

function renderTimeline() {
    const att = state.alerts.filter(a => a.sev !== 'Normal' && state.tlCats.has(a.cat));
    const B = CONFIG.BUCKET_MS, bk = {};
    att.forEach(a => { const k = Math.floor(a.ts / B) * B; (bk[k] = bk[k] || { Critical: 0, Warning: 0 })[a.sev]++; });
    const keys = Object.keys(bk).map(Number).sort((x, y) => x - y);
    const xs = keys.map(k => new Date(k + B / 2));
    const traces = [
        { x: xs, y: keys.map(k => bk[k].Critical), name: 'Critical', type: 'bar', marker: { color: '#FF2D2D' }, yaxis: 'y' },
        { x: xs, y: keys.map(k => bk[k].Warning),  name: 'Warning',  type: 'bar', marker: { color: '#FF8C42' }, yaxis: 'y' },
        { x: att.map(a => a.ts), y: att.map(a => a.cat), type: 'scatter', mode: 'markers', showlegend: false, yaxis: 'y2',
          marker: { color: att.map(a => SEV[a.sev].color), size: att.map(a => 6 + a.conf / 12), opacity: .85,
                    line: { color: 'rgba(255,255,255,.3)', width: .5 } },
          text: att.map(a => `<b>${a.cat}</b><br>${a.ts.toLocaleTimeString()}<br>${a.conf}% · ${a.src}`), hoverinfo: 'text' },
    ];
    const btn = (count, label) => ({ count, label, step: 'minute', stepmode: 'backward' });
    const layout = DARK({
        uirevision: 'tl', barmode: 'stack', hovermode: 'closest', margin: { t: 34, b: 28, l: 92, r: 12 },
        xaxis: { type: 'date', gridcolor: GRID, rangeslider: { visible: true, thickness: .1, bgcolor: 'rgba(255,255,255,.03)' },
                 rangeselector: { buttons: [btn(1, '1m'), btn(5, '5m'), btn(15, '15m'), { step: 'all', label: 'All' }],
                                  bgcolor: 'rgba(255,255,255,.05)', activecolor: '#E07020', font: { color: '#F0EBE5', size: 10 } } },
        yaxis:  { domain: [.56, 1], gridcolor: GRID, title: { text: 'Attacks / ' + CONFIG.BUCKET_MS / 1000 + 's', font: { size: 9 } } },
        yaxis2: { domain: [.06, .46], type: 'category', gridcolor: GRID, categoryorder: 'array',
                  categoryarray: CATEGORIES().filter(c => c !== BENIGN()) },
        legend: { orientation: 'h', x: 1, xanchor: 'right', y: 1.13 },
    });
    Plotly.react('timeline-chart', traces, layout, PCFG);
}

/* ════════════ MODEL COMPARISON (E5) ════════════ */
function renderModels() {
    const sel = MODELS.filter(m => state.mdlSel.has(m.key));
    const best = (k, dir) => sel.length ? (dir === 'min' ? Math.min : Math.max)(...sel.map(m => m[k])) : null;
    const cols = [['acc', 'Accuracy', 'max', v => v.toFixed(2) + '%'], ['prec', 'Macro P', 'max', v => v.toFixed(3)],
                  ['rec', 'Macro R', 'max', v => v.toFixed(3)], ['f1', 'Macro F1', 'max', v => v.toFixed(3)],
                  ['fpr', 'Macro FPR', 'min', v => v.toFixed(3) + '%']];
    const winner = sel.length ? sel.reduce((p, m) => m.f1 > p.f1 ? m : p) : null;   // primary metric = Macro F1
    $('#mdl-table').innerHTML =
        `<div class="cmp-row six cmp-head"><span>Model</span>${cols.map(c => `<span>${c[1]}</span>`).join('')}</div>` +
        sel.map(m => `<div class="cmp-row six"><span class="cmp-model ${m === winner ? 'cmp-best' : ''}">${m === winner ? '🏆 ' : ''}${m.name}</span>` +
            cols.map(([k, , dir, f]) => `<span class="${m[k] === best(k, dir) ? 'cmp-best' : ''}">${f(m[k])}</span>`).join('') + '</div>').join('');

    const metrics = [['Accuracy', 'acc'], ['Macro precision', 'prec'], ['Macro recall', 'rec'], ['Macro F1', 'f1']];
    const val = (m, k) => k === 'acc' ? m.acc : m[k] * 100;
    Plotly.react('mdl-chart', sel.map(m => ({
        type: 'bar', name: m.name, x: metrics.map(x => x[0]), y: metrics.map(([, k]) => val(m, k)),
        text: metrics.map(([, k]) => val(m, k).toFixed(1)), textposition: 'outside', textfont: { size: 9, color: '#F0EBE5' },
        marker: { color: MODEL_COLOR[m.key] },
    })), DARK({ barmode: 'group', margin: { t: 14, b: 34, l: 34, r: 8 }, yaxis: { range: [0, 112], gridcolor: GRID, ticksuffix: '%' },
                legend: { orientation: 'h', y: -0.22 } }), PCFG);

    setText('#mdl-note', winner ? `Best by primary metric (Macro F1): ${winner.name}. Macro FPR is averaged over all 15 classes — see the Errors tab for the benign false-alarm rate. Source: final_technical_performance_report.md.` : 'Select at least one model.');
}

function updateModelsLive() {
    const box = $('#mdl-live'); if (!box || !tabActive('compare')) return;
    const withM = state.alerts.filter(a => a.models.rf && a.models.lstm);
    const last = [...state.alerts].reverse().find(a => a.sev !== 'Normal') || state.alerts[state.alerts.length - 1];
    if (!last) { box.innerHTML = '<div class="empty">Waiting for alerts…</div>'; return; }
    const agree = withM.length ? Math.round(withM.filter(a => a.models.rf.cls === a.models.lstm.cls && a.models.lstm.cls === a.cls).length / withM.length * 100) : null;
    const rows = MODELS.filter(m => state.mdlSel.has(m.key)).map(m => {
        const p = last.models[m.key]; if (!p) return `<div class="mbar"><div class="mbar-top"><span>${m.name}</span><b>n/a</b></div></div>`;
        const c = confColor(p.conf);
        return `<div class="mbar"><div class="mbar-top"><span style="color:${MODEL_COLOR[m.key]}">● ${m.name}</span><span><b>${catName(p.cls)}</b> · <b style="color:${c}">${p.conf}%</b></span></div>
                <div class="conf-bar-track"><div class="conf-bar-fill" style="width:${p.conf}%;background:${c}"></div></div></div>`;
    }).join('');
    box.innerHTML = rows + (agree != null ? `<div class="note">All three models agree on ${agree}% of the ${withM.length} flows seen this session.</div>` : '');
}

/* ════════════ ERROR ANALYSIS (E6) ════════════ */
function errStats(key) {
    const cats = CATEGORIES(), ix = c => cats.indexOf(c);
    const G = cats.map(() => cats.map(() => 0));
    CONFUSION[key].forEach((row, i) => row.forEach((v, j) => { G[ix(catName(i))][ix(catName(j))] += v; }));
    const b = ix(BENIGN());
    const fpBy = cats.map((_, j) => j === b ? 0 : G[b][j]);                                   // benign flagged as attack j
    const fnBy = cats.map((_, i) => i === b ? 0 : G[i][b]);                                   // attack i called benign
    const mix  = cats.map((_, i) => i === b ? 0 : sum(G[i]) - G[i][i] - G[i][b]);             // attack i called another attack
    const total = sum(G.map(sum)), errors = total - sum(G.map((r, i) => r[i]));
    const pairs = [];
    cats.forEach((t, i) => cats.forEach((p, j) => { if (i !== j && G[i][j] > 0) pairs.push({ t, p, n: G[i][j] }); }));
    pairs.sort((x, y) => y.n - x.n);
    return { cats, G, b, fpBy, fnBy, mix, total, errors, pairs, benTotal: sum(G[b]),
             atkTotal: sum(G.flatMap((r, i) => i === b ? [] : r)), fp: sum(fpBy), fn: sum(fnBy), mixTotal: sum(mix) };
}

function renderErrors() {
    const sel = MODELS.filter(m => state.errSel.has(m.key));
    const S = {}; sel.forEach(m => { S[m.key] = errStats(m.key); });
    const attackCats = CATEGORIES().filter(c => c !== BENIGN());
    const xs = state.errCat === 'All' ? attackCats : [state.errCat];

    Plotly.react('err-chart', sel.map(m => {
        const s = S[m.key], arr = state.errMetric === 'fp' ? s.fpBy : s.fnBy;
        return { type: 'bar', name: m.name, x: xs, y: xs.map(c => arr[s.cats.indexOf(c)]), marker: { color: MODEL_COLOR[m.key] } };
    }), DARK({ barmode: 'group', margin: { t: 10, b: 62, l: 40, r: 8 }, yaxis: { gridcolor: GRID, title: { text: state.errMetric === 'fp' ? 'False alarms (benign → attack)' : 'Missed attacks (attack → benign)', font: { size: 9 } } },
                xaxis: { tickangle: -30 }, legend: { orientation: 'h', y: -0.4 } }), PCFG);

    $('#err-cards').innerHTML = sel.map(m => {
        const s = S[m.key], c = state.errCat, j = s.cats.indexOf(c);
        const pairs = (c === 'All' ? s.pairs : s.pairs.filter(p => p.t === c || p.p === c)).slice(0, 4);
        const top = s.pairs[0];
        const lines = c === 'All'
            ? [['False alarms (benign → attack)', `${fmtN(s.fp)} · ${(s.fp / s.benTotal * 100).toFixed(2)}% of benign`],
               ['Missed attacks (attack → benign)', `${fmtN(s.fn)} · ${(s.fn / s.atkTotal * 100).toFixed(2)}% of attacks`],
               ['Attack-type mix-ups', fmtN(s.mixTotal)],
               ['Total errors', `${fmtN(s.errors)} · ${(s.errors / s.total * 100).toFixed(2)}%`]]
            : [[`False alarms labelled ${c}`, fmtN(s.fpBy[j])], [`Missed ${c}`, fmtN(s.fnBy[j])],
               [`${c} confused as another attack`, fmtN(s.mix[j])],
               [`Other attacks mislabelled as ${c}`, fmtN(sum(s.cats.map((_, i) => (i === j || i === s.b) ? 0 : s.G[i][j])))]];
        return `<div class="err-card"><div class="err-head" style="color:${MODEL_COLOR[m.key]}">● ${m.name}</div>
            ${top && c === 'All' ? `<div class="insight">🔎 ${Math.round(top.n / s.errors * 100)}% of errors: ${top.t} → ${top.p}</div>` : ''}
            ${lines.map(([k, v]) => `<div class="kv"><span>${k}</span><b>${v}</b></div>`).join('')}
            <div class="kv-title">Top confusions</div>
            ${pairs.length ? pairs.map(p => `<div class="kv"><span>${p.t} → ${p.p}</span><b>${fmtN(p.n)}</b></div>`).join('') : '<div class="kv"><span>None</span></div>'}</div>`;
    }).join('');
}

/* ════════════ EXPLAINABILITY: SHAP + LIME (E2) ════════════ */
function renderExplainGlobal() {
    const g = GLOBAL_SHAP.slice().reverse();
    Plotly.react('ex-global', [{ type: 'bar', orientation: 'h', y: g.map(x => x[0]), x: g.map(x => x[1]), marker: { color: '#E07020' } }],
        DARK({ margin: { t: 4, b: 30, l: 128, r: 10 }, xaxis: { gridcolor: GRID, title: { text: 'Mean |SHAP value|', font: { size: 9 } } } }), PCFG);
}

function explainOptions() {
    const sel = $('#ex-alert'), att = state.alerts.filter(a => a.sev !== 'Normal').slice(-30).reverse();
    sel.innerHTML = '<option value="latest">Latest alert (auto)</option>' +
        att.map(a => `<option value="${a.id}">${a.ts.toLocaleTimeString()} · ${a.cat} · ${a.conf}%</option>`).join('');
    sel.value = [...sel.options].some(o => o.value === String(state.exSel)) ? String(state.exSel) : 'latest';
    state.exSel = sel.value;
}

function divBars(items) {
    const max = Math.max(...items.map(i => Math.abs(i.v)), 1e-9);
    return items.map(i => `<div class="dv-row"><span class="dv-lab">${i.name}</span>
        <div class="dv-track"><div class="dv-bar ${i.v >= 0 ? 'pos' : 'neg'}" style="width:${Math.abs(i.v) / max * 50}%;${i.v >= 0 ? 'left:50%' : 'right:50%'}"></div></div>
        <span class="dv-val">${i.v >= 0 ? '+' : ''}${i.v.toFixed(3)}</span></div>`).join('');
}

function renderExplain() {
    const box = $('#ex-detail'), att = state.alerts.filter(a => a.sev !== 'Normal');
    const a = state.exSel === 'latest' ? att[att.length - 1] : state.alerts.find(x => String(x.id) === state.exSel);
    if (!a) { box.innerHTML = '<div class="empty">No attack alerts yet.</div>'; return; }
    const S = a.shap.map(f => ({ name: f.name, v: f.shap })), L = a.lime.map(f => ({ name: f.name, v: f.weight }));
    const top5 = arr => new Set(arr.slice().sort((x, y) => Math.abs(y.v) - Math.abs(x.v)).slice(0, 5).map(f => f.name));
    const ts = top5(S), tl = top5(L), shared = [...ts].filter(n => tl.has(n));
    const lvl = shared.length >= 4 ? ['High', '#00D084'] : shared.length === 3 ? ['Moderate', '#FF8C42'] : ['Low', '#FF2D2D'];
    box.innerHTML = `<div class="shap-box">💡 ${a.sentence}</div>
        <div class="ex-cols">
            <div><div class="detail-col-title">SHAP · TreeExplainer</div>${divBars(S)}</div>
            <div><div class="detail-col-title">LIME · local surrogate</div>${L.length ? divBars(L) : '<div class="empty">LIME not provided by backend yet.</div>'}</div>
        </div>
        ${L.length ? `<div class="agree" style="border-color:${lvl[1]}"><b style="color:${lvl[1]}">Agreement: ${lvl[0]}</b> — ${shared.length}/5 top features shared${shared.length ? ' (' + shared.join(', ') + ')' : ''}</div>` : ''}
        <div class="note">Bars to the right push toward "${a.cat}", bars to the left push against it. Scales are relative within each method. ${confLabel()}: ${a.conf}%.</div>`;
}

/* ════════════ PDF REPORT (E10) ════════════ */
async function downloadReport() {
    if (!window.jspdf) { alert('PDF library not loaded (jsPDF needs internet via the CDN).'); return; }
    const btn = $('#export-btn'), old = btn.textContent; btn.disabled = true; btn.textContent = 'Generating…';
    try {
        const doc = new window.jspdf.jsPDF({ unit: 'mm', format: 'a4' });
        const W = 210, M = 15; let y = 0;
        const need = h => { if (y + h > 282) { doc.addPage(); y = 18; } };
        const heading = t => { need(14); y += 4; doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(11, 31, 58);
                               doc.text(t, M, y); doc.setDrawColor(224, 112, 32); doc.line(M, y + 1.5, W - M, y + 1.5); y += 7; };
        const row = (k, v) => { need(6); doc.setFont('helvetica', 'bold'); doc.setFontSize(9); doc.setTextColor(90);
                                doc.text(k, M, y); doc.setFont('helvetica', 'normal'); doc.setTextColor(30); doc.text(String(v), M + 38, y); y += 5.5; };

        const A = state.alerts, attacks = A.filter(a => a.sev !== 'Normal'), now = new Date();
        doc.setFillColor(11, 31, 58); doc.rect(0, 0, W, 26, 'F');
        doc.setTextColor(255); doc.setFont('helvetica', 'bold'); doc.setFontSize(16); doc.text('NIDS - Intrusion Detection Report', M, 12);
        doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.text('AI-Powered Network Intrusion Detection System', M, 19);
        y = 30;

        heading('Report details');
        row('Date', now.toLocaleDateString()); row('Time', now.toLocaleTimeString());
        row('Source', state.mode === 'live' ? 'Live capture' : 'PCAP: ' + (state.pcapName || '-'));
        row('Model used', CONFIG.MODEL_USED); row('Dataset', CONFIG.DATASET);
        row('Confidence', CONFIG.CONFIDENCE_CALIBRATED ? 'Temperature-calibrated' : 'Uncalibrated (highest class probability)');
        row('Class scheme', CONFIG.USE_GROUPS ? '8 attack categories (grouped)' : '15 CICIDS-2017 classes');

        heading('Prediction summary');
        const crit = A.filter(a => a.sev === 'Critical').length, warn = A.filter(a => a.sev === 'Warning').length;
        row('Flows analysed', fmtN(A.length)); row('Critical alerts', crit); row('Warnings', warn);
        row('Normal flows', A.length - crit - warn);
        row('Avg. confidence', attacks.length ? (sum(attacks.map(a => a.conf)) / attacks.length).toFixed(1) + '% (attacks)' : '-');

        const byCat = {}; attacks.forEach(a => { (byCat[a.cat] = byCat[a.cat] || []).push(a.conf); });
        const catRows = Object.entries(byCat).sort((p, q) => q[1].length - p[1].length);
        heading('Attack statistics');
        doc.setFont('helvetica', 'bold'); doc.setFontSize(9); doc.setTextColor(90);
        doc.text('Attack type', M, y); doc.text('Count', M + 70, y); doc.text('Avg. confidence', M + 95, y); y += 5;
        doc.setFont('helvetica', 'normal'); doc.setTextColor(30);
        catRows.forEach(([c, v]) => { need(6); doc.text(c, M, y); doc.text(String(v.length), M + 70, y); doc.text((sum(v) / v.length).toFixed(1) + '%', M + 95, y); y += 5; });
        if (!catRows.length) { doc.text('No attacks recorded in this session.', M, y); y += 5; }

        // charts (light theme so they print well)
        const L = (extra) => Object.assign({ paper_bgcolor: '#fff', plot_bgcolor: '#fff', font: { color: '#222', size: 12 }, margin: { t: 30, b: 50, l: 60, r: 14 } }, extra);
        const B = CONFIG.BUCKET_MS, bk = {};
        attacks.forEach(a => { const k = Math.floor(a.ts / B) * B; (bk[k] = bk[k] || { Critical: 0, Warning: 0 })[a.sev]++; });
        const keys = Object.keys(bk).map(Number).sort((p, q) => p - q), xs = keys.map(k => new Date(k + B / 2));
        const img1 = await Plotly.toImage({ data: [
            { x: xs, y: keys.map(k => bk[k].Critical), name: 'Critical', type: 'bar', marker: { color: '#D92D2D' } },
            { x: xs, y: keys.map(k => bk[k].Warning), name: 'Warning', type: 'bar', marker: { color: '#F08C42' } }],
            layout: L({ title: { text: 'Attack timeline', font: { size: 14 } }, barmode: 'stack', legend: { orientation: 'h', y: -0.2 } }) },
            { format: 'png', width: 900, height: 320 });
        const img2 = await Plotly.toImage({ data: [{ type: 'bar', orientation: 'h', y: catRows.map(r => r[0]).reverse(), x: catRows.map(r => r[1].length).reverse(), marker: { color: '#E07020' } }],
            layout: L({ title: { text: 'Attacks by type', font: { size: 14 } }, margin: { t: 30, b: 40, l: 130, r: 14 } }) }, { format: 'png', width: 600, height: 340 });
        const mets = [['Accuracy', 'acc'], ['Macro F1', 'f1']];
        const img3 = await Plotly.toImage({ data: MODELS.map(m => ({ type: 'bar', name: m.name, x: mets.map(x => x[0]), y: mets.map(([, k]) => k === 'acc' ? m.acc : m[k] * 100), marker: { color: MODEL_COLOR[m.key] } })),
            layout: L({ title: { text: 'Model comparison (%)', font: { size: 14 } }, barmode: 'group', legend: { orientation: 'h', y: -0.25 } }) }, { format: 'png', width: 600, height: 340 });

        heading('Charts');
        need(62); doc.addImage(img1, 'PNG', M, y, 180, 64); y += 68;
        need(56); doc.addImage(img2, 'PNG', M, y, 88, 50); doc.addImage(img3, 'PNG', M + 92, y, 88, 50); y += 54;

        heading('Recent alerts (latest 15 attacks)');
        attacks.slice(-15).reverse().forEach(a => {
            const lines = doc.splitTextToSize(a.sentence, W - 2 * M);
            need(10 + lines.length * 4);
            doc.setFont('helvetica', 'bold'); doc.setFontSize(9); doc.setTextColor(30);
            doc.text(`${a.ts.toLocaleTimeString()}   ${a.cat}   [${a.sev}]   ${a.conf}%`, M, y);
            doc.setFont('helvetica', 'normal'); doc.setTextColor(90); doc.text(`${a.src} -> ${a.dst}:${a.port}`, W - M, y, { align: 'right' }); y += 4.5;
            doc.setFontSize(8); doc.setTextColor(70); doc.text(lines, M, y); y += lines.length * 4 + 3;
        });

        const pages = doc.getNumberOfPages();
        for (let p = 1; p <= pages; p++) { doc.setPage(p); doc.setFontSize(8); doc.setTextColor(140); doc.text(`Page ${p} of ${pages}`, W / 2, 292, { align: 'center' }); }
        doc.save(`NIDS_Report_${now.toISOString().slice(0, 19).replace(/[:T]/g, '-')}.pdf`);
    } catch (e) { console.error(e); alert('Report generation failed: ' + e.message); }
    btn.disabled = false; btn.textContent = old;
}

/* ════════════ WIRING ════════════ */
function activateTab(name) {
    $$('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    $$('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
    if (name === 'timeline') renderTimeline();
    if (name === 'compare') { renderModels(); updateModelsLive(); }
    if (name === 'errors') renderErrors();
    if (name === 'explain') { explainOptions(); renderExplainGlobal(); renderExplain(); }
}

function setStatus(s) {
    const el = $('#live-status');
    el.textContent = s === 'mock' ? '● Demo data stream' : s === 'live' ? '● Connected to backend' : '● Backend disconnected';
    el.style.color = s === 'closed' ? 'var(--red)' : s === 'mock' ? 'var(--orange)' : 'var(--green)';
}

function connect() {
    stopAlertStream();
    if (state.mode === 'live') {
        if (API.USE_MOCK) seedHistory(onAlert);
        startAlertStream(onAlert, setStatus, true);
    } else if (!API.USE_MOCK) startAlertStream(onAlert, setStatus, false);
}

$$('.mode-btn').forEach(btn => btn.addEventListener('click', function () {
    $$('.mode-btn').forEach(b => b.classList.remove('active')); this.classList.add('active');
    state.mode = this.dataset.mode; const live = state.mode === 'live';
    $('#pcap-upload-box').style.display = live ? 'none' : 'block';
    $('#live-status').style.display = live ? 'block' : 'none';
    setText('#page-mode', live ? 'Live Monitoring' : 'PCAP Analysis');
    resetAlerts(); connect();
}));

$('#pcap-upload-box').addEventListener('click', () => $('#pcap-input').click());
$('#pcap-input').addEventListener('click', e => e.stopPropagation());
$('#pcap-input').addEventListener('change', async function () {
    if (!this.files.length) return;
    const f = this.files[0]; state.pcapName = f.name;
    setText('#upload-filename', f.name); resetAlerts();
    try {
        await uploadPcap(f, onAlert, (i, n) => setText('#upload-label', `Analysing… ${i}/${n}`));
        setText('#upload-label', '✅ Analysis complete');
    } catch (e) { setText('#upload-label', '❌ ' + e.message); }
});

$('#thresh-slider').addEventListener('input', function () { state.minConf = +this.value; setText('#thresh-val', this.value + '%'); renderFeed(); });
$$('.sev-cb').forEach(cb => cb.addEventListener('change', () => {
    state.sevs = new Set($$('.sev-cb:checked').map(c => c.value)); renderFeed();
}));
$('#sort-btn').addEventListener('click', function () {
    state.sortBy = state.sortBy === 'time' ? 'conf' : 'time';
    this.textContent = state.sortBy === 'time' ? 'Sort: Time ↕' : 'Sort: Confidence ↕'; renderFeed();
});
$$('.tab-btn').forEach(b => b.addEventListener('click', () => activateTab(b.dataset.tab)));

// timeline controls
const attackCats = () => CATEGORIES().filter(c => c !== BENIGN());
const buildTlChips = () => chips($('#tl-chips'), attackCats(), state.tlCats, renderTimeline);
buildTlChips();
$('#tl-all').onclick  = () => { attackCats().forEach(c => state.tlCats.add(c)); buildTlChips(); renderTimeline(); };
$('#tl-none').onclick = () => { state.tlCats.clear(); buildTlChips(); renderTimeline(); };
$('#tl-live').onclick = function () { state.tlLive = !state.tlLive; this.classList.toggle('on', state.tlLive); this.textContent = state.tlLive ? '● Live' : '⏸ Paused'; };

// model + error controls
chips($('#mdl-chips'), MODELS.map(m => m.key), state.mdlSel, () => { renderModels(); updateModelsLive(); }, k => MODELS.find(m => m.key === k).name);
chips($('#err-chips'), MODELS.map(m => m.key), state.errSel, renderErrors, k => MODELS.find(m => m.key === k).name);
$('#err-cat').innerHTML = ['All', ...attackCats()].map(c => `<option value="${c}">${c === 'All' ? 'All attack categories' : c}</option>`).join('');
$('#err-cat').onchange = function () { state.errCat = this.value; renderErrors(); };
$$('#err-metric .chip').forEach(b => b.onclick = () => {
    state.errMetric = b.dataset.m; $$('#err-metric .chip').forEach(x => x.classList.toggle('on', x === b)); renderErrors();
});
$('#ex-alert').onchange = function () { state.exSel = this.value; renderExplain(); };
$('#export-btn').addEventListener('click', downloadReport);

connect();
setInterval(updateCards, 5000);      // keep "last minute" / "5 min" figures fresh