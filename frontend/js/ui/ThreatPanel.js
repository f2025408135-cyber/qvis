/**
 * ThreatPanel — Slide-in detail panel for backend info and threat evidence.
 *
 * Enhanced for DEF CON presentation with:
 *  - Empty state screens
 *  - Error boundaries per render
 *  - Breadcrumb navigation
 *  - Keyboard-accessible close (Escape)
 *  - Clipboard fallback for older browsers
 */
import { sanitize } from '../utils.js';

export class ThreatPanel {
    constructor(container) {
        this.container = container;
        this.isOpen = false;
        this.history = []; // For breadcrumb-style navigation

        // Global keyboard handler
        this._keyHandler = (e) => {
            if (e.key === 'Escape' && this.isOpen) {
                this.close();
            }
        };
        document.addEventListener('keydown', this._keyHandler);

        // Listen for panel open events
        document.addEventListener('openThreatPanel', (e) => {
            try {
                if (e.detail.backend) {
                    this.renderBackend(e.detail.backend, e.detail.threats || []);
                } else if (e.detail.threat) {
                    this.renderThreat(e.detail.threat);
                }
                this.open();
            } catch (err) {
                console.error('[ThreatPanel] Render error:', err);
                this.renderError('Failed to render panel content');
                this.open();
            }
        });
    }

    open() {
        this.isOpen = true;
        this.container.style.transform = 'translateX(0)';
        this.container.classList.add('open');
    }

    close() {
        this.isOpen = false;
        this.container.style.transform = 'translateX(100%)';
        this.container.classList.remove('open');
        this.history = [];
    }

    _escape(str) {
        if (!str) return '';
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    }

    /** Render an error state inside the panel. */
    renderError(message) {
        this.container.innerHTML = `
            <div class="panel-header">
                <h2>ERROR</h2>
                <button class="close-btn" id="tp-close-btn" aria-label="Close panel">&times;</button>
            </div>
            <div class="panel-error-state">
                <div class="error-icon-sm">&#x26A0;</div>
                <p>${this._escape(message || 'An unexpected error occurred')}</p>
                <button class="action-btn" id="tp-retry-btn">RETRY</button>
            </div>
        `;
        this._attachCloseButton();
        const retryBtn = document.getElementById('tp-retry-btn');
        if (retryBtn) {
            retryBtn.addEventListener('click', () => {
                this.close();
            });
        }
    }

    renderBackend(backend, threats) {
        try {
            const safeName = this._escape(backend.name);
            const safePlatform = this._escape(backend.platform);
            const platformClass = safePlatform.replace(/_/g, '-');
            const safeQubits = this._escape(String(backend.num_qubits));
            const isOp = backend.operational;
            const isSim = backend.is_simulator;

            let html = `
                <div class="panel-header">
                    <h2>${safeName}</h2>
                    <button class="close-btn" id="tp-close-btn" aria-label="Close panel">&times;</button>
                </div>

                <div class="panel-section">
                    <span class="badge ${platformClass}">${safePlatform.toUpperCase()}</span>
                    <div class="meta-grid">
                        <div>Qubits: <span class="white">${safeQubits}</span></div>
                        <div>Status: <span class="${isOp ? 'green' : 'red'}">${isOp ? 'ONLINE' : 'OFFLINE'}</span></div>
                        <div>Type: <span class="white">${isSim ? 'SIMULATOR' : 'HARDWARE'}</span></div>
                        <div>Threat: <span class="${this._severityClass(backend.threat_level)}">${this._escape((backend.threat_level || 'none').toUpperCase())}</span></div>
                    </div>
                </div>

                <h3>ACTIVE THREATS (${threats.length})</h3>
                <div class="threat-list">
            `;

            if (threats.length === 0) {
                html += `
                    <div class="empty-state">
                        <div class="empty-state-icon">&#x2713;</div>
                        <p>No active threats detected on this backend.</p>
                        <p class="empty-state-sub">System operating within normal parameters.</p>
                    </div>
                `;
            }

            threats.forEach((t, i) => {
                const safeTechId = this._escape(t.technique_id);
                const safeTitle = this._escape(t.title);
                const safeSeverity = this._escape(t.severity);
                const safeEffect = this._escape(t.visual_effect || 'none');
                html += `
                    <div class="threat-card" id="tc-${i}" data-index="${i}" role="button" tabindex="0" aria-label="View threat ${safeTechId}">
                        <div class="threat-card-header">
                            <span class="${safeSeverity}-text">&#x25A0;</span> ${safeTechId}
                        </div>
                        <div class="threat-card-title">${safeTitle}</div>
                        <div class="threat-card-meta">Effect: ${safeEffect}</div>
                    </div>
                `;
            });

            html += `</div>`;

            this.container.innerHTML = html;

            this._attachCloseButton();

            // Card click handlers
            threats.forEach((t, i) => {
                const card = document.getElementById(`tc-${i}`);
                if (card) {
                    const handler = () => {
                        document.dispatchEvent(new CustomEvent('openThreatPanel', { detail: { threat: t } }));
                    };
                    card.onclick = handler;
                    card.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handler(); } };
                }
            });

        } catch (e) {
            console.error('[ThreatPanel] renderBackend error:', e);
            this.renderError('Failed to render backend details');
        }
    }

    renderThreat(threat) {
        try {
            const safeTechId = this._escape(threat.technique_id);
            const safeSeverity = this._escape(threat.severity);
            const safeTitle = this._escape(threat.title);
            const safeDesc = this._escape(threat.description);
            const safeTechniqueName = this._escape(threat.technique_name || '');

            // Evidence section
            let evidenceHtml = '';
            if (threat.evidence && Object.keys(threat.evidence).length > 0) {
                for (const [key, value] of Object.entries(threat.evidence)) {
                    evidenceHtml += `<div><span class="dim">${this._escape(key)}:</span> <span class="white">${this._escape(String(value))}</span></div>`;
                }
            } else {
                evidenceHtml = `<div class="dim">No evidence data available for this threat.</div>`;
            }

            // Remediation section
            let remediationHtml = '';
            if (threat.remediation && threat.remediation.length > 0) {
                threat.remediation.forEach((r, i) => {
                    remediationHtml += `
                        <label class="remediation-item">
                            <input type="checkbox" id="rem-${i}"> <span>${this._escape(r)}</span>
                        </label>
                    `;
                });
            } else {
                remediationHtml = `<div class="dim">No remediation steps defined.</div>`;
            }

            const html = `
                <div class="panel-header">
                    <button class="back-btn" id="tp-back-btn" aria-label="Go back">&larr;</button>
                    <h2>THREAT DETAIL</h2>
                    <button class="close-btn" id="tp-close-btn" aria-label="Close panel">&times;</button>
                </div>

                <div class="panel-section">
                    <div class="threat-detail-header">
                        <span class="badge technique-badge">${safeTechId}</span>
                        <span class="${safeSeverity}-text severity-label">${safeSeverity.toUpperCase()}</span>
                    </div>
                    <h3 class="white" style="margin: 15px 0;">${safeTitle}</h3>
                    <p class="description">${safeDesc}</p>
                    <p class="technique-name">${safeTechniqueName}</p>
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

                <div class="panel-actions">
                    <button class="action-btn" id="tp-copy-btn">
                        COPY REPORT JSON
                    </button>
                    <button class="action-btn action-btn-secondary" id="tp-remediate-btn">
                        MARK REMEDIATED
                    </button>
                </div>
            `;

            this.container.innerHTML = html;

            this._attachCloseButton();

            // Back button
            const backBtn = document.getElementById('tp-back-btn');
            if (backBtn) {
                backBtn.addEventListener('click', () => this.close());
            }

            // Copy button with fallback
            const copyBtn = document.getElementById('tp-copy-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', async () => {
                    try {
                        const json = JSON.stringify(threat, null, 2);
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            await navigator.clipboard.writeText(json);
                        } else {
                            // Fallback: textarea + execCommand
                            const ta = document.createElement('textarea');
                            ta.value = json;
                            ta.style.position = 'fixed';
                            ta.style.opacity = '0';
                            document.body.appendChild(ta);
                            ta.select();
                            document.execCommand('copy');
                            document.body.removeChild(ta);
                        }
                        copyBtn.textContent = 'COPIED';
                        setTimeout(() => { copyBtn.textContent = 'COPY REPORT JSON'; }, 2000);
                    } catch (e) {
                        console.error('[ThreatPanel] Copy failed:', e);
                        copyBtn.textContent = 'COPY FAILED';
                        setTimeout(() => { copyBtn.textContent = 'COPY REPORT JSON'; }, 2000);
                    }
                });
            }

            // Mark remediated button
            const remBtn = document.getElementById('tp-remediate-btn');
            if (remBtn) {
                remBtn.addEventListener('click', () => {
                    const checkboxes = this.container.querySelectorAll('.remediation-item input[type="checkbox"]');
                    const checked = this.container.querySelectorAll('.remediation-item input[type="checkbox"]:checked');
                    if (checked.length === 0) {
                        // Check all as a convenience
                        checkboxes.forEach(cb => cb.checked = true);
                        remBtn.textContent = `${checkboxes.length} ITEMS MARKED`;
                    } else {
                        remBtn.textContent = `${checked.length}/${checkboxes.length} REMEDIATED`;
                    }
                });
            }

        } catch (e) {
            console.error('[ThreatPanel] renderThreat error:', e);
            this.renderError('Failed to render threat details');
        }
    }

    /** Helper to attach close button handler. */
    _attachCloseButton() {
        const closeBtn = document.getElementById('tp-close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.close());
        }
    }

    /** Map severity to CSS class. */
    _severityClass(level) {
        const map = {
            critical: 'critical-text',
            high: 'high-text',
            medium: 'medium-text',
            low: 'low-text',
            info: 'info-text',
            none: 'info-text'
        };
        return map[level] || 'info-text';
    }

    /** Cleanup (call when destroying). */
    destroy() {
        document.removeEventListener('keydown', this._keyHandler);
    }
}
