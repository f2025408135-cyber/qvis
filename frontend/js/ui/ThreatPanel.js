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

    sanitize(str) {
        if (!str) return '';
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    }

    renderBackend(backend, threats) {
        const safeName = this.sanitize(backend.name);
        const safePlatform = this.sanitize(backend.platform);
        const platformClass = safePlatform.replace('_', '-');
        
        let html = `
            <div class="panel-header">
                <h2>${safeName}</h2>
                <button class="close-btn" id="tp-close-btn">×</button>
            </div>
            
            <div class="panel-section">
                <span class="badge ${platformClass}">${safePlatform.toUpperCase()}</span>
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
        
        threats.forEach((t, i) => {
            const safeTechId = this.sanitize(t.technique_id);
            const safeTitle = this.sanitize(t.title);
            const safeSeverity = this.sanitize(t.severity);
            html += `
                <div class="threat-card" id="tc-${i}" data-index="${i}">
                    <div class="threat-card-header">
                        <span class="${safeSeverity}-text">■</span> ${safeTechId}
                    </div>
                    <div class="threat-card-title">${safeTitle}</div>
                </div>
            `;
        });
        
        html += `</div>`;
        
        this.container.innerHTML = html;
        
        // Attach event listeners
        document.getElementById('tp-close-btn').addEventListener('click', () => this.close());
        
        threats.forEach((t, i) => {
            document.getElementById(`tc-${i}`).addEventListener('click', () => {
                document.dispatchEvent(new CustomEvent('openThreatPanel', { detail: { threat: t } }));
            });
        });
    }

    renderThreat(threat) {
        const safeTechId = this.sanitize(threat.technique_id);
        const safeSeverity = this.sanitize(threat.severity);
        const safeTitle = this.sanitize(threat.title);
        const safeDesc = this.sanitize(threat.description);

        let evidenceHtml = '';
        for (const [key, value] of Object.entries(threat.evidence)) {
            evidenceHtml += `<div><span class="dim">${this.sanitize(key)}:</span> <span class="white">${this.sanitize(String(value))}</span></div>`;
        }
        
        let remediationHtml = '';
        threat.remediation.forEach(r => {
            remediationHtml += `
                <label class="remediation-item">
                    <input type="checkbox"> <span>${this.sanitize(r)}</span>
                </label>
            `;
        });
        
        let html = `
            <div class="panel-header">
                <h2>THREAT DETAIL</h2>
                <button class="close-btn" id="tp-close-btn">×</button>
            </div>
            
            <div class="panel-section">
                <div class="threat-detail-header">
                    <span class="badge technique-badge">${safeTechId}</span>
                    <span class="${safeSeverity}-text severity-label">${safeSeverity.toUpperCase()}</span>
                </div>
                <h3 class="white" style="margin: 15px 0;">${safeTitle}</h3>
                <p class="description">${safeDesc}</p>
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
            
            <button class="action-btn" id="tp-copy-btn">
                COPY REPORT JSON
            </button>
        `;
        
        this.container.innerHTML = html;

        document.getElementById('tp-close-btn').addEventListener('click', () => this.close());
        
        document.getElementById('tp-copy-btn').addEventListener('click', () => {
            navigator.clipboard.writeText(JSON.stringify(threat, null, 2));
        });
    }
}
