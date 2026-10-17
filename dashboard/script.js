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