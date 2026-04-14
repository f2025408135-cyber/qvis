/**
 * QVis — Threat Timeline Component
 * Horizontal scrollable timeline bar showing threat events chronologically.
 */

const SEVERITY_COLORS = {
    critical: '#ff3333',
    high: '#ff7722',
    medium: '#ffbb00',
    low: '#33cc66',
    info: '#4488cc',
};

export class Timeline {
    constructor(container) {
        this.container = container;
        this.threats = [];
        this.tooltipEl = null;
        this._knownIds = new Set();
        this.initDOM();
        this.fetchHistory();

        // Subscribe to live WebSocket snapshot updates
        document.addEventListener('snapshotUpdate', (e) => {
            const snapshot = e.detail;
            if (snapshot && snapshot.threats) {
                let added = false;
                for (const threat of snapshot.threats) {
                    if (!this._knownIds.has(threat.id)) {
                        this._knownIds.add(threat.id);
                        this.threats.push(threat);
                        added = true;
                    }
                }
                if (added) this.render();
            }
        });
    }

    initDOM() {
        this.container.innerHTML = `
            <div id="timeline-bar">
                <div id="timeline-header">
                    <span class="timeline-title">THREAT TIMELINE</span>
                    <span id="timeline-count" class="timeline-count">0 events</span>
                </div>
                <div id="timeline-track">
                    <div id="timeline-dots"></div>
                </div>
            </div>
            <div id="timeline-tooltip" class="timeline-tooltip" style="display:none;"></div>
        `;

        this.dotsContainer = document.getElementById('timeline-dots');
        this.countEl = document.getElementById('timeline-count');
        this.trackEl = document.getElementById('timeline-track');
        this.tooltipEl = document.getElementById('timeline-tooltip');

        // Inject styles if not already present
        if (!document.getElementById('timeline-styles')) {
            const style = document.createElement('style');
            style.id = 'timeline-styles';
            style.textContent = `
                #timeline-bar {
                    position: fixed;
                    bottom: 0;
                    left: 0;
                    right: 0;
                    height: 72px;
                    background: #0a0a0f;
                    border-top: 1px solid rgba(255,255,255,0.06);
                    display: flex;
                    flex-direction: column;
                    z-index: 100;
                    font-family: monospace;
                    pointer-events: auto;
                }
                #timeline-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 4px 16px 0 16px;
                    flex-shrink: 0;
                }
                .timeline-title {
                    color: #888;
                    font-size: 10px;
                    letter-spacing: 2px;
                }
                .timeline-count {
                    color: #556;
                    font-size: 10px;
                }
                #timeline-track {
                    flex: 1;
                    overflow-x: auto;
                    overflow-y: hidden;
                    padding: 6px 16px 8px 16px;
                    scrollbar-width: thin;
                    scrollbar-color: #223 #0a0a0f;
                }
                #timeline-track::-webkit-scrollbar {
                    height: 4px;
                }
                #timeline-track::-webkit-scrollbar-track {
                    background: #0a0a0f;
                }
                #timeline-track::-webkit-scrollbar-thumb {
                    background: #223;
                    border-radius: 2px;
                }
                #timeline-dots {
                    display: flex;
                    align-items: center;
                    gap: 0;
                    min-width: max-content;
                    height: 100%;
                    position: relative;
                }
                .timeline-dot {
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    flex-shrink: 0;
                    cursor: pointer;
                    transition: transform 0.15s ease, box-shadow 0.15s ease;
                    position: relative;
                }
                .timeline-dot:hover {
                    transform: scale(1.8);
                }
                .timeline-dot::after {
                    content: '';
                    position: absolute;
                    top: 50%;
                    left: 100%;
                    width: 18px;
                    height: 1px;
                    background: rgba(255,255,255,0.08);
                }
                .timeline-dot:last-child::after {
                    display: none;
                }
                .timeline-tooltip {
                    position: fixed;
                    bottom: 80px;
                    background: #111118;
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 4px;
                    padding: 10px 14px;
                    color: #e0e0e0;
                    font-family: monospace;
                    font-size: 11px;
                    line-height: 1.5;
                    z-index: 200;
                    pointer-events: none;
                    max-width: 320px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.6);
                }
                .tooltip-severity {
                    display: inline-block;
                    padding: 1px 6px;
                    border-radius: 2px;
                    font-size: 9px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-bottom: 4px;
                }
                .tooltip-title {
                    font-weight: bold;
                    font-size: 12px;
                    margin-bottom: 4px;
                }
                .tooltip-meta {
                    color: #888;
                    font-size: 10px;
                }
            `;
            document.head.appendChild(style);
        }
    }

    async fetchHistory() {
        try {
            const backendHost = location.port === '3000'
                ? '127.0.0.1:8000'
                : (location.host || '127.0.0.1:8000');
            const token = window.__QVIS_WS_TOKEN || '';
            const url = `${location.protocol}//${backendHost}/api/threats/history${token ? '?token=' + token : ''}`;

            const resp = await fetch(url);
            if (!resp.ok) return;
            this.threats = await resp.json();
            // Track known IDs to deduplicate against live updates
            this.threats.forEach(t => this._knownIds.add(t.id));
            this.render();
        } catch (e) {
            console.warn('[Timeline] Failed to fetch threat history:', e);
        }
    }

    addThreat(threat) {
        this.threats.push(threat);
        this.render();
    }

    render() {
        if (!this.dotsContainer) return;

        // Sort by detected_at
        const sorted = [...this.threats].sort((a, b) => {
            const ta = new Date(a.detected_at).getTime();
            const tb = new Date(b.detected_at).getTime();
            return ta - tb;
        });

        this.countEl.textContent = `${sorted.length} event${sorted.length !== 1 ? 's' : ''}`;

        this.dotsContainer.innerHTML = sorted.map((threat, i) => {
            const color = SEVERITY_COLORS[threat.severity] || '#4488cc';
            const severity = threat.severity || 'info';
            const title = threat.title || threat.technique_name || 'Unknown';
            const detected = threat.detected_at ? new Date(threat.detected_at).toLocaleTimeString() : '';
            const backend = threat.backend_id || '';
            const technique = threat.technique_id || '';

            return `<div class="timeline-dot"
                data-index="${i}"
                style="background:${color}; box-shadow: 0 0 6px ${color}44;"
                data-title="${this._esc(title)}"
                data-severity="${this._esc(severity)}"
                data-color="${color}"
                data-detected="${this._esc(detected)}"
                data-backend="${this._esc(backend)}"
                data-technique="${this._esc(technique)}"
                data-description="${this._esc(threat.description || '')}"
            ></div>`;
        }).join('');

        // Attach hover listeners
        this.dotsContainer.querySelectorAll('.timeline-dot').forEach(dot => {
            dot.addEventListener('mouseenter', (e) => this._showTooltip(e, dot));
            dot.addEventListener('mouseleave', () => this._hideTooltip());
            dot.addEventListener('mousemove', (e) => this._moveTooltip(e));
        });
    }

    _showTooltip(e, dot) {
        if (!this.tooltipEl) return;
        this.tooltipEl.style.display = 'block';
        const color = dot.dataset.color;
        this.tooltipEl.innerHTML = `
            <span class="tooltip-severity" style="background:${color}22; color:${color};">${dot.dataset.severity}</span>
            <div class="tooltip-title">${dot.dataset.title}</div>
            <div class="tooltip-meta">${dot.dataset.backend ? 'Backend: ' + dot.dataset.backend + '<br>' : ''}${dot.dataset.technique ? 'Technique: ' + dot.dataset.technique + '<br>' : ''}${dot.dataset.detected}</div>
        `;
        this._moveTooltip(e);
    }

    _moveTooltip(e) {
        if (!this.tooltipEl) return;
        const x = Math.min(e.clientX + 12, window.innerWidth - 340);
        this.tooltipEl.style.left = x + 'px';
        this.tooltipEl.style.transform = 'translateX(0)';
    }

    _hideTooltip() {
        if (!this.tooltipEl) return;
        this.tooltipEl.style.display = 'none';
    }

    _esc(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
}
