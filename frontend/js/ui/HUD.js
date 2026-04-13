/**
 * HUD — Top-level dashboard showing statistics, connection status,
 * system diagnostics, and the live threat ticker.
 *
 * Enhanced for DEF CON presentation with:
 *  - Real-time connection metrics
 *  - Collection timing display
 *  - FPS toggle button
 *  - Reconnection progress
 *  - System health indicators
 */
import { sanitize } from '../utils.js';

export class HUD {
    constructor(container) {
        this.container = container;
        this.initDOM();
    }

    initDOM() {
        this.container.innerHTML = `
            <div class="hud-header">
                <div class="hud-title">
                    <span class="title-accent">QVIS</span> — QUANTUM THREAT TOPOLOGY ENGINE
                </div>
                <div class="hud-status-container">
                    <div id="data-status" class="status-pill disconnected">DEMO MODE</div>
                    <div id="connection-status" class="status-pill disconnected">DISCONNECTED</div>
                    <button id="fps-toggle" class="hud-icon-btn" title="Toggle performance monitor (Ctrl+F)" aria-label="Toggle FPS counter">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                        </svg>
                    </button>
                </div>
            </div>

            <div id="demo-banner" class="demo-banner" style="display: none;">
                DEMO MODE — connect credentials to enable live quantum platform data
            </div>

            <div id="reconnect-info" class="reconnect-banner" style="display: none;"></div>

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
                <div class="stat-group stat-group-sm">
                    <div class="stat-value info-text" id="stat-backends">0</div>
                    <div class="stat-label">BACKENDS</div>
                </div>
                <div class="stat-group stat-group-sm">
                    <div class="stat-value info-text" id="stat-qubits">0</div>
                    <div class="stat-label">QUBITS</div>
                </div>
            </div>

            <div class="hud-meta" id="hud-meta" style="display: none;">
                <div id="meta-collection-time" class="meta-item">Collection: --</div>
                <div id="meta-connection-info" class="meta-item">WS: --</div>
            </div>

            <div class="threat-ticker" id="threat-ticker"></div>

            <div class="hud-footer">
                <span class="hud-keyboard-hint">Press ? for keyboard shortcuts</span>
            </div>
        `;

        // FPS toggle button
        const fpsBtn = document.getElementById('fps-toggle');
        if (fpsBtn) {
            fpsBtn.addEventListener('click', async () => {
                const { perfMonitor } = await import('../core/PerformanceMonitor.js');
                const enabled = perfMonitor.toggle();
            });
        }
    }

    /**
     * Update HUD with latest snapshot data.
     *
     * @param {Object} snapshot - The SimulationSnapshot from the backend.
     */
    update(snapshot) {
        if (!snapshot) return;

        const severityCounts = snapshot.threats_by_severity || {};

        // Critical count with flash animation
        const critEl = document.getElementById('stat-critical');
        if (critEl) {
            const oldCrit = parseInt(critEl.textContent) || 0;
            const newCrit = severityCounts['critical'] || 0;
            critEl.textContent = newCrit;
            if (newCrit > oldCrit) {
                critEl.classList.remove('flash-red');
                void critEl.offsetWidth; // Force reflow for re-animation
                critEl.classList.add('flash-red');
            }
        }

        const highEl = document.getElementById('stat-high');
        if (highEl) highEl.textContent = severityCounts['high'] || 0;

        const mediumEl = document.getElementById('stat-medium');
        if (mediumEl) mediumEl.textContent = severityCounts['medium'] || 0;

        const backendsEl = document.getElementById('stat-backends');
        if (backendsEl) backendsEl.textContent = snapshot.backends ? snapshot.backends.length : 0;

        const qubitsEl = document.getElementById('stat-qubits');
        if (qubitsEl) qubitsEl.textContent = snapshot.total_qubits || 0;

        // Threat ticker
        const ticker = document.getElementById('threat-ticker');
        if (ticker && snapshot.threats) {
            ticker.innerHTML = '';

            if (snapshot.threats.length === 0) {
                const emptyTag = document.createElement('div');
                emptyTag.className = 'threat-tag threat-tag-empty';
                emptyTag.textContent = 'No active threats — all systems nominal';
                ticker.appendChild(emptyTag);
            } else {
                snapshot.threats.forEach(t => {
                    const tag = document.createElement('div');

                    const safeSeverity = sanitize(t.severity);
                    const safeTechId = sanitize(t.technique_id);
                    const safeTitle = sanitize(t.title);

                    tag.className = `threat-tag border-${safeSeverity}`;
                    tag.innerHTML = `<span class="${safeSeverity}-text">[${safeTechId}]</span> ${safeTitle}`;
                    tag.setAttribute('role', 'button');
                    tag.setAttribute('tabindex', '0');
                    tag.setAttribute('aria-label', `View threat: ${safeTitle}`);

                    const clickHandler = () => {
                        document.dispatchEvent(new CustomEvent('openThreatPanel', { detail: { threat: t } }));
                    };
                    tag.onclick = clickHandler;
                    tag.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); clickHandler(); } };

                    ticker.appendChild(tag);
                });
            }
        }

        // Data source status
        const dataStatusEl = document.getElementById('data-status');
        const demoBannerEl = document.getElementById('demo-banner');
        const metaEl = document.getElementById('hud-meta');

        const meta = snapshot.collection_metadata || {};
        const source = meta.source || 'MockCollector';
        const degraded = meta.degraded || false;

        if (source === 'IBMQuantumCollector') {
            demoBannerEl.style.display = 'none';
            if (degraded) {
                if (dataStatusEl) {
                    dataStatusEl.className = 'status-pill degraded';
                    dataStatusEl.textContent = 'DEGRADED — CACHED';
                }
            } else {
                if (dataStatusEl) {
                    dataStatusEl.className = 'status-pill live';
                    dataStatusEl.textContent = 'LIVE — IBM Quantum';
                }
            }
        } else {
            demoBannerEl.style.display = 'block';
            if (dataStatusEl) {
                dataStatusEl.className = 'status-pill disconnected';
                dataStatusEl.textContent = 'DEMO MODE';
            }
        }

        // Meta information
        if (metaEl && meta.elapsed_ms !== undefined) {
            metaEl.style.display = 'flex';
            const timeEl = document.getElementById('meta-collection-time');
            if (timeEl) timeEl.textContent = `Collection: ${meta.elapsed_ms}ms`;
        }
    }
}
