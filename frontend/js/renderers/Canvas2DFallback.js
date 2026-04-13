/**
 * Canvas2DFallback — Impressive 2D canvas renderer for environments without WebGL.
 * 
 * When Three.js or WebGL isn't available, this renderer kicks in and provides
 * a visually compelling 2D representation of the quantum threat topology.
 * Features:
 *  - Animated backend nodes with orbital particles
 *  - Connection lines between entangled backends
 *  - Threat severity color coding
 *  - Pulsing, glowing effects using 2D compositing
 *  - Smooth animations at 60fps on Canvas 2D
 */

export class Canvas2DFallback {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.backends = [];
        this.entanglements = [];
        this.threats = [];
        this.particles = [];
        this.time = 0;
        this.running = false;
        this._rafId = null;
        this._lastTime = 0;

        this.resize();
        window.addEventListener('resize', () => this.resize());
    }

    resize() {
        this.width = window.innerWidth;
        this.height = window.innerHeight;
        this.canvas.width = this.width;
        this.canvas.height = this.height;
    }

    /** Update the visualization with new snapshot data. */
    updateData(snapshot) {
        // Update backends
        snapshot.backends.forEach((backend, index) => {
            let existing = this.backends.find(b => b.id === backend.id);
            if (!existing) {
                existing = {
                    id: backend.id,
                    name: backend.name,
                    platform: backend.platform,
                    num_qubits: backend.num_qubits,
                    is_simulator: backend.is_simulator,
                    threatLevel: backend.threat_level,
                    radius: Math.sqrt(backend.num_qubits) * 2,
                    angle: (index / Math.max(snapshot.backends.length, 1)) * Math.PI * 2,
                    orbitRadius: Math.min(this.width, this.height) * 0.2,
                    pulsePhase: Math.random() * Math.PI * 2,
                    particles: []
                };

                // Generate orbital particles
                const particleCount = Math.min(Math.ceil(backend.num_qubits / 5), 20);
                for (let i = 0; i < particleCount; i++) {
                    existing.particles.push({
                        angle: (i / particleCount) * Math.PI * 2,
                        distance: existing.radius * 2 + Math.random() * 30,
                        speed: 0.5 + Math.random() * 1.5,
                        size: 1 + Math.random() * 2,
                        opacity: 0.3 + Math.random() * 0.5
                    });
                }

                this.backends.push(existing);
            }
            existing.threatLevel = backend.threat_level;
        });

        // Remove backends no longer in snapshot
        const activeIds = new Set(snapshot.backends.map(b => b.id));
        this.backends = this.backends.filter(b => activeIds.has(b.id));

        // Update entanglements
        this.entanglements = snapshot.entanglement_pairs.map(pair => ({
            a: pair[0],
            b: pair[1]
        }));

        // Update threats
        this.threats = snapshot.threats || [];
    }

    /** Start the render loop. */
    start() {
        this.running = true;
        this._lastTime = performance.now();
        this._animate();
    }

    /** Stop the render loop. */
    stop() {
        this.running = false;
        if (this._rafId) {
            cancelAnimationFrame(this._rafId);
            this._rafId = null;
        }
    }

    _animate() {
        if (!this.running) return;
        this._rafId = requestAnimationFrame(() => this._animate());

        const now = performance.now();
        const dt = (now - this._lastTime) / 1000;
        this._lastTime = now;
        this.time += dt;

        this._render();
    }

    _render() {
        const ctx = this.ctx;
        const w = this.width;
        const h = this.height;
        const cx = w / 2;
        const cy = h / 2;

        // Clear with fade trail
        ctx.fillStyle = 'rgba(2, 4, 8, 0.15)';
        ctx.fillRect(0, 0, w, h);

        // Background grid
        this._drawGrid(ctx, w, h);

        // Get backend positions
        const positions = new Map();
        this.backends.forEach(backend => {
            const x = cx + Math.cos(backend.angle) * backend.orbitRadius;
            const y = cy + Math.sin(backend.angle) * backend.orbitRadius * 0.6;
            positions.set(backend.id, { x, y });
        });

        // Draw entanglement connections
        this.entanglements.forEach(pair => {
            const posA = positions.get(pair.a);
            const posB = positions.get(pair.b);
            if (posA && posB) {
                this._drawEntanglement(ctx, posA, posB);
            }
        });

        // Draw backends and their particles
        this.backends.forEach(backend => {
            const pos = positions.get(backend.id);
            if (!pos) return;
            this._drawBackend(ctx, backend, pos.x, pos.y);
        });

        // Draw threat indicators
        this._drawThreatHUD(ctx, w, h);

        // Fallback mode indicator
        ctx.save();
        ctx.font = '12px monospace';
        ctx.fillStyle = 'rgba(255, 153, 68, 0.6)';
        ctx.textAlign = 'right';
        ctx.fillText('2D FALLBACK MODE — WebGL unavailable', w - 20, h - 20);
        ctx.restore();
    }

    _drawGrid(ctx, w, h) {
        ctx.save();
        ctx.strokeStyle = 'rgba(17, 34, 68, 0.3)';
        ctx.lineWidth = 0.5;
        const gridSize = 60;

        for (let x = 0; x < w; x += gridSize) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }
        for (let y = 0; y < h; y += gridSize) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
        ctx.restore();
    }

    _drawEntanglement(ctx, posA, posB) {
        ctx.save();

        // Bezier curve
        const midX = (posA.x + posB.x) / 2;
        const midY = (posA.y + posB.y) / 2 - 40;
        const pulse = Math.sin(this.time * 3) * 0.3 + 0.7;

        ctx.strokeStyle = `rgba(64, 216, 160, ${0.15 * pulse})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(posA.x, posA.y);
        ctx.quadraticCurveTo(midX, midY, posB.x, posB.y);
        ctx.stroke();

        // Traveling particle along curve
        const t = (this.time * 0.3) % 1;
        const px = (1-t)*(1-t)*posA.x + 2*(1-t)*t*midX + t*t*posB.x;
        const py = (1-t)*(1-t)*posA.y + 2*(1-t)*t*midY + t*t*posB.y;

        ctx.fillStyle = `rgba(128, 255, 204, ${0.8 * pulse})`;
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI * 2);
        ctx.fill();

        ctx.restore();
    }

    _drawBackend(ctx, backend, x, y) {
        ctx.save();

        const severityColors = {
            critical: '#ff3333',
            high: '#ff8833',
            medium: '#3388ff',
            low: '#22cc88',
            info: '#6688aa',
            none: '#335577'
        };

        const platformColors = {
            ibm_quantum: '#2255bb',
            amazon_braket: '#22aaff',
            azure_quantum: '#0078d4'
        };

        const baseColor = platformColors[backend.platform] || '#335577';
        const threatColor = severityColors[backend.threatLevel] || baseColor;
        const pulse = Math.sin(this.time * 2 + backend.pulsePhase) * 0.3 + 0.7;

        // Glow effect
        const gradient = ctx.createRadialGradient(x, y, 0, x, y, backend.radius * 3);
        gradient.addColorStop(0, threatColor + '40');
        gradient.addColorStop(0.5, threatColor + '10');
        gradient.addColorStop(1, 'transparent');
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(x, y, backend.radius * 3 * pulse, 0, Math.PI * 2);
        ctx.fill();

        // Core sphere
        const coreGrad = ctx.createRadialGradient(x - backend.radius * 0.3, y - backend.radius * 0.3, 0, x, y, backend.radius);
        coreGrad.addColorStop(0, threatColor);
        coreGrad.addColorStop(1, baseColor);
        ctx.fillStyle = coreGrad;
        ctx.beginPath();
        ctx.arc(x, y, backend.radius, 0, Math.PI * 2);
        ctx.fill();

        // Orbit ring
        ctx.strokeStyle = `rgba(255, 255, 255, ${0.1 * pulse})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.ellipse(x, y, backend.radius * 2, backend.radius * 0.5, Math.PI / 6, 0, Math.PI * 2);
        ctx.stroke();

        // Orbital particles
        backend.particles.forEach(p => {
            p.angle += p.speed * 0.016;
            const px = x + Math.cos(p.angle) * p.distance;
            const py = y + Math.sin(p.angle) * p.distance * 0.4;
            ctx.fillStyle = `rgba(100, 180, 255, ${p.opacity * pulse})`;
            ctx.beginPath();
            ctx.arc(px, py, p.size, 0, Math.PI * 2);
            ctx.fill();
        });

        // Label
        ctx.font = '11px monospace';
        ctx.fillStyle = 'rgba(180, 210, 255, 0.7)';
        ctx.textAlign = 'center';
        ctx.fillText(backend.name, x, y + backend.radius + 20);
        ctx.fillStyle = 'rgba(180, 210, 255, 0.4)';
        ctx.fillText(`${backend.num_qubits}q`, x, y + backend.radius + 34);

        ctx.restore();
    }

    _drawThreatHUD(ctx, w, h) {
        ctx.save();

        // Threat summary in top-right
        const severityCounts = {};
        this.threats.forEach(t => {
            severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
        });

        let yPos = 80;
        const colors = { critical: '#ff3333', high: '#ff8833', medium: '#3388ff' };

        ctx.textAlign = 'right';
        Object.entries(colors).forEach(([severity, color]) => {
            const count = severityCounts[severity] || 0;
            ctx.font = 'bold 28px monospace';
            ctx.fillStyle = color;
            ctx.fillText(count.toString(), w - 30, yPos);
            ctx.font = '11px monospace';
            ctx.fillStyle = 'rgba(180, 210, 255, 0.5)';
            ctx.fillText(severity.toUpperCase(), w - 30, yPos + 16);
            yPos += 50;
        });

        // Title
        ctx.textAlign = 'left';
        ctx.font = '16px monospace';
        ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
        ctx.fillText('QVIS — QUANTUM THREAT TOPOLOGY', 25, 35);

        ctx.restore();
    }
}
