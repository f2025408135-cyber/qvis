/**
 * UI Component displaying top-level statistics and the live threat ticker.
 */
import { sanitize } from '../utils.js';

export class HUD {
    /**
     * Mounts the layout scaffolding handling HUD components.
     * 
     * @param {HTMLElement} container - Web UI anchor rendering the absolute structure dynamically.
     */
    constructor(container) {
        this.container = container;
        this.initDOM();
    }

    /**
     * Recreates standardized scaffolding elements parsing styles correctly natively modifying CSS.
     */
    initDOM() {
        this.container.innerHTML = `
            <div class="hud-header">
                <div class="hud-title">QVIS — QUANTUM THREAT TOPOLOGY ENGINE</div>
                <div class="hud-status-container">
                    <div id="data-status" class="status-pill disconnected">DEMO MODE</div>
                    <div id="connection-status" class="status-pill disconnected">DISCONNECTED</div>
                </div>
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

    /**
     * Reads parsed `SimulationSnapshot` payloads extracting numeric statistics tracking
     * updates rendering DOM counts conditionally alerting visual flashes dynamically.
     * 
     * @param {Object} snapshot - Target snapshot JSON mapped handling parameters accurately rendering visuals natively.
     */
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
            
            const safeSeverity = sanitize(t.severity);
            const safeTechId = sanitize(t.technique_id);
            const safeTitle = sanitize(t.title);
            
            tag.className = `threat-tag border-${safeSeverity}`;
            tag.innerHTML = `<span class="${safeSeverity}-text">[${safeTechId}]</span> ${safeTitle}`;
            
            tag.onclick = () => {
                document.dispatchEvent(new CustomEvent('openThreatPanel', { detail: { threat: t } }));
            };
            
            ticker.appendChild(tag);
        });

        // Update data source status indicator based on snapshot metadata
        const dataStatusEl = document.getElementById('data-status');
        const demoBannerEl = document.getElementById('demo-banner');
        
        const meta = snapshot.collection_metadata || {};
        const source = meta.source || "MockCollector";
        const degraded = meta.degraded || false;

        if (source === "IBMQuantumCollector") {
            demoBannerEl.style.display = 'none';
            if (degraded) {
                dataStatusEl.className = 'status-pill disconnected'; // visually yellow/red fallback
                dataStatusEl.style.color = '#ffaa00';
                dataStatusEl.style.borderColor = '#ffaa00';
                dataStatusEl.textContent = 'DEGRADED — CACHED';
            } else {
                dataStatusEl.className = 'status-pill live';
                dataStatusEl.textContent = 'LIVE — IBM Quantum';
            }
        } else {
            demoBannerEl.style.display = 'block';
            dataStatusEl.className = 'status-pill disconnected';
            dataStatusEl.style.color = '#ff9944';
            dataStatusEl.style.borderColor = '#ff9944';
            dataStatusEl.textContent = 'DEMO MODE';
        }
    }
}
