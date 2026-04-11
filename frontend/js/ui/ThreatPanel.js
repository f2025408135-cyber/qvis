export class ThreatPanel {
    constructor(container) {
        this.container = container;
        this.isOpen = false;
        
        document.addEventListener('openThreatPanel', (e) => {
            if (e.detail.backend) {
                this.renderBackend(e.detail.backend, e.detail.threats);
            } else if (e.detail.threat) {
                this.renderThreat(e.detail.threat);
            }
            this.open();
        });
    }

    open() {
        this.isOpen = true;
        this.container.style.transform = 'translateX(0)';
    }

    close() {
        this.isOpen = false;
        this.container.style.transform = 'translateX(100%)';
    }

    renderBackend(backend, threats) {
        const platformClass = backend.platform.replace('_', '-');
        
        let html = `
            <div class="panel-header">
                <h2>${backend.name}</h2>
                <button class="close-btn" onclick="document.getElementById('threat-panel').__vue__.close()">×</button>
            </div>
            
            <div class="panel-section">
                <span class="badge ${platformClass}">${backend.platform.toUpperCase()}</span>
                <div class="meta-grid">
                    <div>Qubits: <span class="white">${backend.num_qubits}</span></div>
                    <div>Status: <span class="${backend.operational ? 'green' : 'red'}">${backend.operational ? 'ONLINE' : 'OFFLINE'}</span></div>
                    <div>Type: <span class="white">${backend.is_simulator ? 'SIMULATOR' : 'HARDWARE'}</span></div>
                </div>
            </div>
            
            <h3>ACTIVE THREATS (${threats.length})</h3>
            <div class="threat-list">
        `;
        
        if (threats.length === 0) {
            html += `<div class="empty-state">No active threats detected.</div>`;
        }
        
        threats.forEach(t => {
            html += `
                <div class="threat-card" onclick="document.dispatchEvent(new CustomEvent('openThreatPanel', { detail: { threat: ${JSON.stringify(t).replace(/"/g, '&quot;')} } }))">
                    <div class="threat-card-header">
                        <span class="${t.severity}-text">■</span> ${t.technique_id}
                    </div>
                    <div class="threat-card-title">${t.title}</div>
                </div>
            `;
        });
        
        html += `</div>`;
        
        this.container.innerHTML = html;
        this.container.__vue__ = this;
    }

    renderThreat(threat) {
        let evidenceHtml = '';
        for (const [key, value] of Object.entries(threat.evidence)) {
            evidenceHtml += `<div><span class="dim">${key}:</span> <span class="white">${value}</span></div>`;
        }
        
        let remediationHtml = '';
        threat.remediation.forEach(r => {
            remediationHtml += `
                <label class="remediation-item">
                    <input type="checkbox"> <span>${r}</span>
                </label>
            `;
        });
        
        let html = `
            <div class="panel-header">
                <h2>THREAT DETAIL</h2>
                <button class="close-btn" onclick="document.getElementById('threat-panel').__vue__.close()">×</button>
            </div>
            
            <div class="panel-section">
                <div class="threat-detail-header">
                    <span class="badge technique-badge">${threat.technique_id}</span>
                    <span class="${threat.severity}-text severity-label">${threat.severity.toUpperCase()}</span>
                </div>
                <h3 class="white" style="margin: 15px 0;">${threat.title}</h3>
                <p class="description">${threat.description}</p>
            </div>
            
            <div class="panel-section">
                <h3>EVIDENCE</h3>
                <div class="evidence-box">
                    ${evidenceHtml}
                </div>
            </div>
            
            <div class="panel-section">
                <h3>REMEDIATION</h3>
                <div class="remediation-list">
                    ${remediationHtml}
                </div>
            </div>
            
            <button class="action-btn" onclick="navigator.clipboard.writeText('${JSON.stringify(threat).replace(/"/g, '&quot;').replace(/'/g, "\\'")}')">
                COPY REPORT JSON
            </button>
        `;
        
        this.container.innerHTML = html;
        this.container.__vue__ = this;
    }
}
