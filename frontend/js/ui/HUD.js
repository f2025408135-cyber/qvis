export class HUD {
    constructor(container) {
        this.container = container;
        this.initDOM();
    }

    initDOM() {
        this.container.innerHTML = `
            <div class="hud-header">
                <div class="hud-title">QVIS — QUANTUM THREAT TOPOLOGY ENGINE</div>
                <div id="connection-status" class="status-pill disconnected">DISCONNECTED</div>
            </div>
            
            <div id="demo-banner" class="demo-banner" style="display: none;">
                DEMO MODE — connect credentials to enable live quantum platform data
            </div>

            <div class="hud-stats">
                <div class="stat-group">
                    <div class="stat-value critical-text" id="stat-critical">0</div>
                    <div class="stat-label">CRITICAL</div>
                </div>
                <div class="stat-group">
                    <div class="stat-value high-text" id="stat-high">0</div>
                    <div class="stat-label">HIGH</div>
                </div>
                <div class="stat-group">
                    <div class="stat-value medium-text" id="stat-medium">0</div>
                    <div class="stat-label">MEDIUM</div>
                </div>
            </div>
            
            <div class="threat-ticker" id="threat-ticker"></div>
        `;
    }

    update(snapshot) {
        const severityCounts = snapshot.threats_by_severity || {};
        
        const critEl = document.getElementById('stat-critical');
        const oldCrit = parseInt(critEl.textContent);
        const newCrit = severityCounts['critical'] || 0;
        critEl.textContent = newCrit;
        if (newCrit > oldCrit) {
            critEl.classList.add('flash-red');
            setTimeout(() => critEl.classList.remove('flash-red'), 500);
        }
        
        document.getElementById('stat-high').textContent = severityCounts['high'] || 0;
        document.getElementById('stat-medium').textContent = severityCounts['medium'] || 0;

        const ticker = document.getElementById('threat-ticker');
        ticker.innerHTML = '';
        
        snapshot.threats.forEach(t => {
            const tag = document.createElement('div');
            tag.className = `threat-tag border-${t.severity}`;
            tag.innerHTML = `<span class="${t.severity}-text">[${t.technique_id}]</span> ${t.title}`;
            
            tag.onclick = () => {
                document.dispatchEvent(new CustomEvent('openThreatPanel', { detail: { threat: t } }));
            };
            
            ticker.appendChild(tag);
        });
        
        document.getElementById('demo-banner').style.display = 'block';
    }
}
