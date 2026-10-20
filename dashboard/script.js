/* WORLD MAP — built only from real attack alerts (no demo locations)
   - no attacks            -> empty map + "Waiting for attack alerts" + empty table
   - attack, private IP    -> stays in the feed, never placed on the map
   - attack, public IP     -> geolocated (approx.); marker + table row if lookup succeeds
   - repeat location       -> count and most common attack type update            */

(() => {
    const mapEl = document.getElementById('threat-map');
    if (!mapEl || typeof Plotly === 'undefined') return;

    const MAX_LOOKUPS_PER_UPDATE = 30;
    const RETRY_FAILED_MS = 5 * 60 * 1000;

    const geoCache = new Map();   // ip -> {lat, lon, city, country}
    const failedAt = new Map();   // ip -> time of last failed lookup
    const inflight = new Map();   // ip -> Promise (de-duplicates concurrent lookups)
    let renderSeq = 0;            // drops stale renders when updates overlap

    const esc = s => String(s).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    const CRITICAL_TYPES = new Set(['DDoS', 'Infiltration', 'Heartbleed']);
    const WARNING_TYPES  = new Set(['Brute Force', 'Port Scan', 'Web Attack', 'DoS Slowloris']);
    const badgeClass = t => CRITICAL_TYPES.has(t) ? 'bc' : WARNING_TYPES.has(t) ? 'bw' : 'bg';

    const baseLayout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        margin: { t: 5, b: 5, l: 5, r: 5 },
        geo: {
            showland: true, landcolor: '#2A1508',
            showocean: true, oceancolor: '#0C0704',
            showcountries: true, countrycolor: '#3D1F0C',
            showcoastlines: true, coastlinecolor: '#3D1F0C',
            bgcolor: 'rgba(0,0,0,0)',
            projection: { type: 'natural earth' }
        },
        hoverlabel: {
            bgcolor: '#1A0D06', bordercolor: '#E07020',
            font: { color: '#F0EBE5', size: 11, family: 'Inter' }
        }
    };

    const note = text => [{
        text, x: 0.5, y: 0.5, xref: 'paper', yref: 'paper',
        showarrow: false, font: { color: '#9B8878', size: 12 }
    }];

    const emptyTrace = {
        type: 'scattergeo', mode: 'markers',
        lat: [], lon: [], text: [], customdata: [],
        marker: { size: [], color: [], opacity: 0.9 },
        hovertemplate: '<b>%{text}</b><br>Observed alerts: %{customdata[0]}' +
                       '<br>Most common: %{customdata[1]}<extra></extra>'
    };

    const plotCfg = { responsive: true, displayModeBar: false };

    Plotly.newPlot(mapEl, [emptyTrace],
        { ...baseLayout, annotations: note('Waiting for attack alerts') }, plotCfg);

    /* ── helpers ─────────────────────────────────────────────── */
    const isAttack = a => a && a.sev !== 'Normal';

    function isPublicIPv4(ip) {
        const p = String(ip || '').split('.');
        if (p.length !== 4 || p.some(x => !/^\d{1,3}$/.test(x))) return false;
        const [a, b, c] = p.map(Number);
        if (p.some(x => +x > 255)) return false;
        return !(
            a === 0 || a === 10 || a === 127 || a >= 224 ||
            (a === 100 && b >= 64 && b <= 127) ||               // CGNAT
            (a === 169 && b === 254) ||                         // link-local
            (a === 172 && b >= 16 && b <= 31) ||                // private
            (a === 192 && b === 168) ||                         // private
            (a === 192 && b === 0 && (c === 0 || c === 2)) ||   // reserved / TEST-NET-1
            (a === 198 && (b === 18 || b === 19)) ||            // benchmarking
            (a === 198 && b === 51 && c === 100) ||             // TEST-NET-2
            (a === 203 && b === 0 && c === 113)                 // TEST-NET-3
        );
    }

    function locate(ip) {
        if (geoCache.has(ip)) return Promise.resolve(geoCache.get(ip));
        if (inflight.has(ip)) return inflight.get(ip);
        if (Date.now() - (failedAt.get(ip) || 0) < RETRY_FAILED_MS) return Promise.resolve(null);

        const p = (async () => {
            try {
                const r = await fetch('https://ipwho.is/' + encodeURIComponent(ip));
                if (!r.ok) throw new Error('HTTP ' + r.status);
                const d = await r.json();
                if (!d.success || !Number.isFinite(d.latitude) || !Number.isFinite(d.longitude))
                    throw new Error('no location');
                const loc = {
                    lat: d.latitude, lon: d.longitude,
                    city: d.city || 'Unknown city',
                    country: d.country || 'Unknown country'
                };
                geoCache.set(ip, loc);
                return loc;
            } catch (err) {
                failedAt.set(ip, Date.now());
                console.warn('IP geolocation unavailable for', ip, err.message);
                return null;
            } finally {
                inflight.delete(ip);
            }
        })();
        inflight.set(ip, p);
        return p;
    }

    function renderTable(sites, emptyMsg) {
        const body  = document.getElementById('attack-table-body');
        const badge = document.getElementById('threat-map-badge');
        if (badge) badge.textContent = `● ${sites.length} ${sites.length === 1 ? 'Location' : 'Locations'}`;
        if (!body) return;

        if (!sites.length) {
            body.innerHTML = `<div class="map-empty" style="padding:14px 4px;font-size:12px;color:#9B8878;">${esc(emptyMsg)}</div>`;
            return;
        }
        body.innerHTML = sites
            .slice().sort((a, b) => b.count - a.count).slice(0, 10)
            .map((s, i) => `
                <div class="tbl-row">
                    <span class="rank">${String(i + 1).padStart(2, '0')}</span>
                    <div><div class="loc-name">${esc(s.city)}</div><div class="loc-ctry">${esc(s.country)}</div></div>
                    <span class="atk-count">${s.count}</span>
                    <span class="badge ${badgeClass(s.type)}">${esc(s.type)}</span>
                </div>`).join('');
    }

    /* ── main entry: app.js calls this with the full alert list ── */
    async function updateThreatMap(alerts) {
        if (!Array.isArray(alerts)) return;
        const seq = ++renderSeq;

        const attacks  = alerts.filter(isAttack);                      // benign never mapped
        const mappable = attacks.filter(a => isPublicIPv4(a.src));     // private IPs skipped

        const toLookUp = [...new Set(mappable.map(a => a.src))]
            .filter(ip => !geoCache.has(ip)).slice(-MAX_LOOKUPS_PER_UPDATE);
        await Promise.all(toLookUp.map(locate));
        if (seq !== renderSeq) return;                                 // a newer update took over

        // group by location: count + most common attack type
        const sitesByKey = new Map();
        for (const a of mappable) {
            const loc = geoCache.get(a.src);
            if (!loc) continue;
            const key = `${loc.city}|${loc.country}`;
            if (!sitesByKey.has(key)) sitesByKey.set(key, { ...loc, count: 0, types: new Map() });
            const s = sitesByKey.get(key);
            s.count++;
            const cat = a.cat || 'Unknown';
            s.types.set(cat, (s.types.get(cat) || 0) + 1);
        }
        const sites = [...sitesByKey.values()].map(s => ({
            ...s, type: [...s.types.entries()].sort((x, y) => y[1] - x[1])[0][0]
        }));

        const emptyMsg = !attacks.length
            ? 'Waiting for attack alerts'
            : 'No attack sources with a locatable public IP yet';

        const trace = sites.length ? {
            ...emptyTrace,
            lat: sites.map(s => s.lat),
            lon: sites.map(s => s.lon),
            text: sites.map(s => `${s.city}, ${s.country}`),
            customdata: sites.map(s => [s.count, s.type]),
            marker: {
                size: sites.map(s => Math.min(30, 8 + Math.sqrt(s.count) * 3)),
                color: sites.map(s => s.count >= 20 ? '#FF2D2D' : s.count >= 5 ? '#FF8C42' : '#E07020'),
                opacity: 0.9,
                line: { color: 'rgba(255,255,255,.3)', width: 1 }
            }
        } : emptyTrace;

        Plotly.react(mapEl, [trace],
            { ...baseLayout, annotations: sites.length ? [] : note(emptyMsg) }, plotCfg);
        renderTable(sites, emptyMsg);
    }

    window.updateThreatMap = updateThreatMap;
    window.addEventListener('resize', () => { if (mapEl.data) Plotly.Plots.resize(mapEl); });

    renderTable([], 'Waiting for attack alerts');
})();