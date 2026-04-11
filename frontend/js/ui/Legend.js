export class Legend {
    constructor(container) {
        this.container = container;
        this.initDOM();
    }
    
    initDOM() {
        this.container.innerHTML = `
            <div class="legend-content">
                <div class="legend-section">
                    <h4>PLATFORMS</h4>
                    <div class="legend-item"><span class="legend-dot" style="background: #2255bb;"></span> IBM Quantum</div>
                    <div class="legend-item"><span class="legend-dot" style="background: #22aaff;"></span> Amazon Braket</div>
                    <div class="legend-item"><span class="legend-dot" style="background: #0078d4;"></span> Azure Quantum</div>
                    <div class="legend-item"><span class="legend-dot" style="background: #335577;"></span> Simulator</div>
                </div>
                
                <div class="legend-section">
                    <h4>THREAT VISUALS</h4>
                    <div class="legend-item"><span class="legend-icon orange">◎</span> Timing Oracle</div>
                    <div class="legend-item"><span class="legend-icon red">▲</span> Credential Leak</div>
                    <div class="legend-item"><span class="legend-icon green">▼</span> Calibration Harvest</div>
                    <div class="legend-item"><span class="legend-icon white">≈</span> Interference</div>
                    <div class="legend-item"><span class="legend-icon dark">●</span> IP Extraction (Vortex)</div>
                </div>
            </div>
        `;
    }
}
