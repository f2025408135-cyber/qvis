import { Backend } from '../simulation/Backend.js';

const PLATFORM_DEFS = [
    { key: 'ibm_quantum',  label: 'IBM Quantum',    color: Backend.getPlatformColor('ibm_quantum') },
    { key: 'amazon_braket', label: 'Amazon Braket',  color: Backend.getPlatformColor('amazon_braket') },
    { key: 'azure_quantum', label: 'Azure Quantum',  color: Backend.getPlatformColor('azure_quantum') },
];

const SIMULATOR_COLOR = 0x335577;

const THREAT_VISUALS = [
    { icon: '◎', cls: 'orange', label: 'Timing Oracle' },
    { icon: '▲', cls: 'red',    label: 'Credential Leak' },
    { icon: '▼', cls: 'green',  label: 'Calibration Harvest' },
    { icon: '≈', cls: 'white',  label: 'Interference' },
    { icon: '●', cls: 'dark',   label: 'IP Extraction (Vortex)' },
    { icon: '⚡', cls: 'red',   label: 'Campaign' },
];

function toHex(colorNum) {
    return '#' + colorNum.toString(16).padStart(6, '0');
}

export class Legend {
    constructor(container) {
        this.container = container;
        this.platformSectionEl = null;
        this.activePlatformKeys = new Set();
        this.initDOM();

        // Listen for snapshot updates to dynamically filter platforms
        document.addEventListener('snapshotUpdate', (e) => {
            if (e.detail && e.detail.backends) {
                this.updatePlatforms(e.detail.backends);
            }
        });
    }

    initDOM() {
        this.container.innerHTML = `
            <div class="legend-content">
                <div class="legend-section">
                    <h4>PLATFORMS</h4>
                    <div id="legend-platforms"></div>
                    <div class="legend-item" id="legend-simulator">
                        <span class="legend-dot" style="background: ${toHex(SIMULATOR_COLOR)};"></span> Simulator
                    </div>
                </div>

                <div class="legend-section">
                    <h4>THREAT VISUALS</h4>
                    <div id="legend-threats">
                        ${THREAT_VISUALS.map(t =>
                            `<div class="legend-item"><span class="legend-icon ${t.cls}">${t.icon}</span> ${t.label}</div>`
                        ).join('')}
                    </div>
                </div>
            </div>
        `;
        this.platformSectionEl = document.getElementById('legend-platforms');
    }

    /**
     * Update the platform section to only show platforms that have
     * at least one backend in the current snapshot data.
     */
    updatePlatforms(backends) {
        // Count backends per platform (excluding simulators)
        const counts = {};
        let hasSimulator = false;

        for (const b of backends) {
            if (b.is_simulator) {
                hasSimulator = true;
                continue;
            }
            counts[b.platform] = (counts[b.platform] || 0) + 1;
        }

        // Build the set of active platform keys
        this.activePlatformKeys = new Set(Object.keys(counts));

        // Re-render platform entries — only those with count > 0
        if (this.platformSectionEl) {
            this.platformSectionEl.innerHTML = PLATFORM_DEFS
                .filter(p => this.activePlatformKeys.has(p.key))
                .map(p => {
                    const hex = toHex(p.color);
                    return `<div class="legend-item">
                        <span class="legend-dot" style="background: ${hex};"></span> ${p.label}
                    </div>`;
                }).join('');
        }

        // Show/hide simulator row
        const simEl = document.getElementById('legend-simulator');
        if (simEl) {
            simEl.style.display = hasSimulator ? '' : 'none';
        }
    }
}
