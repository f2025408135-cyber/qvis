/**
 * PerformanceMonitor — FPS counter, memory stats, and frame time analysis.
 * 
 * Designed for DEF CON live demos — shows the audience that the system is
 * performant. Toggle with Ctrl+Shift+F or the HUD FPS button.
 */

class PerformanceMonitor {
    constructor() {
        this.enabled = false;
        this.frames = 0;
        this.lastTime = performance.now();
        this.fps = 0;
        this.frameTimeMin = Infinity;
        this.frameTimeMax = 0;
        this.frameTimeAvg = 0;
        this.frameTimes = [];
        this.maxFrameTimeSamples = 60;
        this.memory = null;
        this.container = null;
        this._rafId = null;
        this._lastFrameStart = 0;
    }

    /** Create the overlay element. */
    init() {
        this.container = document.createElement('div');
        this.container.id = 'perf-monitor';
        this.container.className = 'perf-monitor';
        this.container.innerHTML = `
            <div class="perf-header">
                <span>PERF</span>
                <span class="perf-fps-value">-- FPS</span>
            </div>
            <div class="perf-bar-container">
                <div class="perf-bar perf-bar-fps" id="perf-fps-bar"></div>
            </div>
            <div class="perf-details">
                <div>Frame: <span id="perf-frametime">--</span>ms</div>
                <div>Min: <span id="perf-ft-min">--</span>ms</div>
                <div>Max: <span id="perf-ft-max">--</span>ms</div>
                <div>Draw: <span id="perf-drawcalls">--</span></div>
                <div>Tris: <span id="perf-triangles">--</span></div>
                ${performance.memory ? '<div>Heap: <span id="perf-memory">--</span></div>' : ''}
            </div>
        `;
        this.container.style.display = 'none';
        document.body.appendChild(this.container);
    }

    /** Toggle visibility. */
    toggle() {
        this.enabled = !this.enabled;
        if (this.container) {
            this.container.style.display = this.enabled ? 'block' : 'none';
        }
        if (this.enabled) {
            this._startMonitoring();
        } else {
            this._stopMonitoring();
        }
        return this.enabled;
    }

    /** Call at the start of each frame (before render). */
    beginFrame() {
        this._lastFrameStart = performance.now();
    }

    /** Call at the end of each frame (after render). */
    endFrame() {
        if (!this._lastFrameStart) return;

        const now = performance.now();
        const frameTime = now - this._lastFrameStart;
        this.frames++;

        // Rolling average
        this.frameTimes.push(frameTime);
        if (this.frameTimes.length > this.maxFrameTimeSamples) {
            this.frameTimes.shift();
        }
        this.frameTimeAvg = this.frameTimes.reduce((a, b) => a + b, 0) / this.frameTimes.length;
        this.frameTimeMin = Math.min(this.frameTimeMin, frameTime);
        this.frameTimeMax = Math.max(this.frameTimeMax, frameTime);

        // FPS calculation (update every 500ms)
        if (now - this.lastTime >= 500) {
            this.fps = Math.round((this.frames * 1000) / (now - this.lastTime));
            this.frames = 0;
            this.lastTime = now;
            this._updateDisplay();

            // Reset min/max periodically
            this.frameTimeMin = Infinity;
            this.frameTimeMax = 0;
        }
    }

    /** Inject Three.js renderer info into display. */
    updateRendererInfo(renderer) {
        if (!this.enabled || !this.container) return;

        const info = renderer.info;
        const drawCallsEl = document.getElementById('perf-drawcalls');
        const trisEl = document.getElementById('perf-triangles');

        if (drawCallsEl) drawCallsEl.textContent = info.render.calls || 0;
        if (trisEl) trisEl.textContent = ((info.render.triangles || 0) / 1000).toFixed(1) + 'k';
    }

    _updateDisplay() {
        if (!this.container || this.container.style.display === 'none') return;

        const fpsEl = this.container.querySelector('.perf-fps-value');
        const fpsBar = document.getElementById('perf-fps-bar');
        const ftEl = document.getElementById('perf-frametime');
        const minEl = document.getElementById('perf-ft-min');
        const maxEl = document.getElementById('perf-ft-max');

        if (fpsEl) {
            fpsEl.textContent = this.fps + ' FPS';
            // Color code: green > 50, yellow > 30, red
            fpsEl.className = 'perf-fps-value ' + 
                (this.fps >= 50 ? 'perf-good' : this.fps >= 30 ? 'perf-warn' : 'perf-bad');
        }

        if (fpsBar) {
            const pct = Math.min((this.fps / 60) * 100, 100);
            fpsBar.style.width = pct + '%';
            fpsBar.className = 'perf-bar perf-bar-fps ' +
                (this.fps >= 50 ? 'perf-good' : this.fps >= 30 ? 'perf-warn' : 'perf-bad');
        }

        if (ftEl) ftEl.textContent = this.frameTimeAvg.toFixed(1);
        if (minEl) minEl.textContent = this.frameTimeMin === Infinity ? '--' : this.frameTimeMin.toFixed(1);
        if (maxEl) maxEl.textContent = this.frameTimeMax.toFixed(1);

        // Memory (Chrome only)
        if (performance.memory) {
            const memEl = document.getElementById('perf-memory');
            if (memEl) {
                const mb = (performance.memory.usedJSHeapSize / 1048576).toFixed(1);
                memEl.textContent = mb + 'MB';
            }
        }
    }

    _startMonitoring() {
        // Nothing extra needed — endFrame() drives it
    }

    _stopMonitoring() {
        this.frames = 0;
        this.lastTime = performance.now();
    }

    /** Get current stats as an object (for HUD integration). */
    getStats() {
        return {
            fps: this.fps,
            frameTimeAvg: this.frameTimeAvg,
            frameTimeMin: this.frameTimeMin === Infinity ? 0 : this.frameTimeMin,
            frameTimeMax: this.frameTimeMax
        };
    }
}

// Singleton
export const perfMonitor = new PerformanceMonitor();
export default PerformanceMonitor;
