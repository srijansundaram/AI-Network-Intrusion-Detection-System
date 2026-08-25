// ── WORLD MAP ──────────────────────────────────────────────────────────────
var sites = [
    { lat:40.71,  lon:-74.01,  name:'New York',  n:312, type:'DDoS'        },
    { lat:39.91,  lon:116.39,  name:'Beijing',   n:248, type:'Infiltration' },
    { lat:55.75,  lon:37.62,   name:'Moscow',    n:187, type:'Brute Force'  },
    { lat:1.35,   lon:103.82,  name:'Singapore', n:94,  type:'Port Scan'    },
    { lat:-23.55, lon:-46.63,  name:'São Paulo', n:67,  type:'Bot'          },
    { lat:51.51,  lon:-0.13,   name:'London',    n:54,  type:'Web Attack'   },
    { lat:35.68,  lon:139.69,  name:'Tokyo',     n:43,  type:'DoS'          },
    { lat:-33.87, lon:151.21,  name:'Sydney',    n:38,  type:'Port Scan'    },
    { lat:28.61,  lon:77.21,   name:'Delhi',     n:31,  type:'Brute Force'  },
    { lat:48.85,  lon:2.35,    name:'Paris',     n:22,  type:'Bot'          },
];

var sz  = sites.map(d => Math.max(7, d.n / 17));
var clr = sites.map(d => d.n > 200 ? '#FF1A1A' : d.n > 100 ? '#FF5500' : d.n > 50 ? '#FF8C00' : '#FFA500');

var mapData = [
    // Outer glow
    { type:'scattergeo', mode:'markers', lat:sites.map(d=>d.lat), lon:sites.map(d=>d.lon),
      marker:{ size:sz.map(s=>s*3.2), color:'rgba(255,45,45,0.07)', line:{width:0} },
      hoverinfo:'skip', showlegend:false },
    // Mid glow
    { type:'scattergeo', mode:'markers', lat:sites.map(d=>d.lat), lon:sites.map(d=>d.lon),
      marker:{ size:sz.map(s=>s*2), color:'rgba(255,45,45,0.15)', line:{width:0} },
      hoverinfo:'skip', showlegend:false },
    // Core
    { type:'scattergeo', mode:'markers+text',
      lat:sites.map(d=>d.lat), lon:sites.map(d=>d.lon),
      text:sites.map(d => d.n > 100 ? d.name : ''),
      textposition:'top right',
      textfont:{ size:9, color:'rgba(255,200,150,0.85)' },
      customdata:sites,
      marker:{
          size:sz, color:clr, opacity:0.92,
          line:{ color:'rgba(255,255,255,0.18)', width:0.5 }
      },
      hovertemplate:'<b>%{customdata.name}</b><br>Attacks: <b>%{customdata.n}</b><br>Type: %{customdata.type}<extra></extra>',
      showlegend:false
    }
];

var mapLayout = {
    paper_bgcolor:'rgba(0,0,0,0)',
    plot_bgcolor:'rgba(0,0,0,0)',
    margin:{ t:0, b:0, l:0, r:0 },
    geo:{
        showland:true,      landcolor:'#2A1508',
        showocean:true,     oceancolor:'#0C0704',
        showcountries:true, countrycolor:'#3D1F0C',
        showcoastlines:true,coastlinecolor:'#3D1F0C',
        showlakes:false,
        bgcolor:'rgba(0,0,0,0)',
        projection:{ type:'natural earth' },
        lataxis:{ range:[-58, 82] },
        lonaxis:{ range:[-165, 175] },
        framewidth:0,
    },
    hoverlabel:{
        bgcolor:'#1A0D06', bordercolor:'#E07020',
        font:{ color:'#F0EBE5', size:11, family:'Inter' }
    }
};

Plotly.newPlot('threat-map', mapData, mapLayout, { responsive:true, displayModeBar:false });

function resizeMap() {
    var panel   = document.querySelector('.threat-panel');
    var header  = panel.querySelector('.panel-header');
    var table   = panel.querySelector('.attack-table');
    var h       = panel.clientHeight - header.offsetHeight - table.offsetHeight - 2;
    document.getElementById('threat-map').style.height = h + 'px';
    Plotly.relayout('threat-map', { height: h });
}
window.addEventListener('resize', resizeMap);
setTimeout(resizeMap, 120);

// ── SIDEBAR: MODE TOGGLE ────────────────────────────────────────────────────
document.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        const isLive = this.dataset.mode === 'live';
        document.getElementById('pcap-upload-box').style.display = isLive ? 'none' : 'block';
        document.getElementById('live-status').style.display = isLive ? 'block' : 'none';
    });
});

document.getElementById('pcap-upload-box').addEventListener('click', () => {
    document.getElementById('pcap-input').click();
});
document.getElementById('pcap-input').addEventListener('change', function() {
    if (this.files.length) {
        document.getElementById('upload-label').textContent = '✅ File selected';
        document.getElementById('upload-filename').textContent = this.files[0].name;
    }
});

// ── SIDEBAR: THRESHOLD SLIDER + SEVERITY FILTER ─────────────────────────────
const threshSlider = document.getElementById('thresh-slider');
const threshVal = document.getElementById('thresh-val');
threshSlider.addEventListener('input', function() {
    threshVal.textContent = this.value + '%';
    applyFilters();
});
document.querySelectorAll('.sev-cb').forEach(cb => cb.addEventListener('change', applyFilters));

function applyFilters() {
    const minConf = parseInt(threshSlider.value);
    const activeSeverities = Array.from(document.querySelectorAll('.sev-cb:checked')).map(cb => cb.value);
    document.querySelectorAll('.activity-item').forEach(item => {
        const conf = parseInt(item.dataset.confidence);
        const sev = item.dataset.severity;
        item.style.display = (conf >= minConf && activeSeverities.includes(sev)) ? 'flex' : 'none';
    });
}
applyFilters();

// ── TABS ─────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        this.classList.add('active');
        document.getElementById('tab-' + this.dataset.tab).classList.add('active');

        if (this.dataset.tab === 'timeline' && !window.timelinePlotted) {
            plotTimeline();
            window.timelinePlotted = true;
        }
    });
});

// ── ALERT EXPAND / COLLAPSE WITH EXPLANATION ────────────────────────────────
document.querySelectorAll('#activity-list .activity-item').forEach(item => {
    const detail = item.querySelector('.a-detail');
    const d = item.dataset;

    detail.innerHTML = `
        <div class="shap-box">💡 ${d.explanation}</div>
        <div class="detail-grid">
            <div>
                <div class="detail-col-title">Traffic Details</div>
                <div class="detail-row"><b>Attack Type:</b> <code>${d.attack}</code></div>
                <div class="detail-row"><b>Severity:</b> <code>${d.severity}</code></div>
                <div class="detail-row"><b>Source IP:</b> <code>${d.src}</code></div>
                <div class="detail-row"><b>Destination IP:</b> <code>${d.dst}</code></div>
                <div class="detail-row"><b>Port:</b> <code>${d.port}</code></div>
                <div class="detail-row"><b>Time:</b> <code>${d.time}</code></div>
            </div>
            <div>
                <div class="detail-col-title">Model Confidence</div>
                <div class="conf-bar-track"><div class="conf-bar-fill" style="width:${d.confidence}%"></div></div>
                <div class="conf-label">${d.confidence}% confidence</div>
            </div>
        </div>
    `;

    item.addEventListener('click', function(e) {
        this.classList.toggle('open');
    });
});

// ── TIMELINE CHART (Plotly) ─────────────────────────────────────────────────
function plotTimeline() {
    const times = ['23:07','23:22','23:31','23:34','23:38','23:41','23:44','23:47','23:50','23:52'];
    const critical = [1,0,0,0,0,1,0,1,0,1];
    const warning  = [0,0,0,1,0,0,0,0,1,0];
    const normal   = [0,1,1,0,1,0,1,0,0,0];

    const traces = [
        { x: times, y: critical, name: 'Critical', type: 'scatter', mode: 'lines+markers', line: { color: '#FF2D2D', shape: 'spline' } },
        { x: times, y: warning,  name: 'Warning',  type: 'scatter', mode: 'lines+markers', line: { color: '#FF8C42', shape: 'spline' } },
        { x: times, y: normal,   name: 'Normal',   type: 'scatter', mode: 'lines+markers', line: { color: '#00D084', shape: 'spline' } },
    ];

    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        margin: { t: 20, b: 40, l: 40, r: 20 },
        font: { color: '#9B8878', size: 10, family: 'Inter' },
        xaxis: { gridcolor: 'rgba(255,255,255,0.05)' },
        yaxis: { gridcolor: 'rgba(255,255,255,0.05)', title: 'Alert Events' },
        legend: { orientation: 'h', y: -0.25 },
        hovermode: 'x unified',
    };

    Plotly.newPlot('timeline-chart', traces, layout, { responsive: true, displayModeBar: false });
}