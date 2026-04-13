export class ParticleSystem {
    constructor(scene) {
        this.scene = scene;
        this.MAX_PARTICLES = 2000;
        this.activeParticles = 0;

        this.geometry = new THREE.BufferGeometry();
        
        this.positions = new Float32Array(this.MAX_PARTICLES * 3);
        this.colors = new Float32Array(this.MAX_PARTICLES * 3);
        this.sizes = new Float32Array(this.MAX_PARTICLES);
        
        this.geometry.setAttribute('position', new THREE.BufferAttribute(this.positions, 3));
        this.geometry.setAttribute('color', new THREE.BufferAttribute(this.colors, 3));
        this.geometry.setAttribute('size', new THREE.BufferAttribute(this.sizes, 1));
        
        this.particleData = [];

        this.material = new THREE.PointsMaterial({
            size: 2.5,
            vertexColors: true,
            transparent: true,
            blending: THREE.AdditiveBlending,
            sizeAttenuation: true,
            depthWrite: false
        });

        this.points = new THREE.Points(this.geometry, this.material);
        this.scene.add(this.points);
    }

    spawnBackendParticles(backend) {
        let particlesToSpawn = Math.min(Math.ceil(backend.num_qubits / 4), 100);
        
        if (this.activeParticles + particlesToSpawn > this.MAX_PARTICLES) {
            particlesToSpawn = this.MAX_PARTICLES - this.activeParticles;
        }

        const baseColor = new THREE.Color(backend.baseColor);

        for (let i = 0; i < particlesToSpawn; i++) {
            const idx = this.activeParticles++;
            
            const radius = backend.radius * 2.0 + Math.random() * (backend.radius * 1.5);
            const speed = (Math.random() * 0.5 + 0.2) * (Math.random() > 0.5 ? 1 : -1);
            const phase = Math.random() * Math.PI * 2;
            
            const pData = {
                backendId: backend.id,
                homeX: backend.position.x,
                homeY: backend.position.y,
                homeZ: backend.position.z,
                orbitRadius: radius,
                orbitSpeed: speed,
                orbitPhase: phase,
                orbitInclination: (Math.random() - 0.5) * Math.PI * 0.5,
                baseColor: baseColor.clone().offsetHSL(0, 0, (Math.random()-0.5)*0.2),
                currentColor: new THREE.Color(),
                alpha: 0.3 + Math.random() * 0.6,
                size: 1.5 + Math.random() * 2.0,
                state: "orbiting",
                threatEffect: null,
                leakVelocity: new THREE.Vector3()
            };
            
            pData.currentColor.copy(pData.baseColor);
            this.particleData.push(pData);
            
            this.sizes[idx] = pData.size;
        }
    }

    triggerThreatEffect(backendId, visual_effect, visual_intensity) {
        this.clearThreatEffects(backendId);
        
        this.particleData.forEach(p => {
            if (p.backendId !== backendId) return;
            
            p.threatEffect = visual_effect;
            
            if (visual_effect === "particle_leak" && Math.random() < visual_intensity * 0.3) {
                p.state = "leaking";
                p.leakVelocity.set(
                    (Math.random() - 0.5) * 5 * visual_intensity,
                    (Math.random() - 0.5) * 5 * visual_intensity,
                    (Math.random() - 0.5) * 5 * visual_intensity
                );
            } else if (visual_effect === "color_bleed" && Math.random() < 0.15) {
                p.currentColor.setHex(0xffaa00);
            } else if (visual_effect === "timing_ring") {
                p.orbitSpeed *= 0.6;
                p.currentColor.lerp(new THREE.Color(0xff8844), 0.8);
            } else if (visual_effect === "calibration_drain") {
                p.currentColor.lerp(new THREE.Color(0x44ffaa), 0.8);
            } else if (visual_effect === "vortex") {
                p.state = "vortex";
            }
        });
    }

    clearThreatEffects(backendId) {
        this.particleData.forEach(p => {
            if (p.backendId === backendId) {
                p.threatEffect = null;
                p.state = "orbiting";
                p.currentColor.copy(p.baseColor);
            }
        });
    }

    update(deltaTime) {
        for (let i = 0; i < this.activeParticles; i++) {
            const p = this.particleData[i];
            
            if (p.state === "orbiting") {
                p.orbitPhase += p.orbitSpeed * deltaTime;
                
                let localX = Math.cos(p.orbitPhase) * p.orbitRadius;
                let localZ = Math.sin(p.orbitPhase) * p.orbitRadius;
                
                let y = localZ * Math.sin(p.orbitInclination);
                localZ = localZ * Math.cos(p.orbitInclination);
                
                y += Math.sin(p.orbitPhase * 2 + i) * 0.3;
                
                this.positions[i*3] = p.homeX + localX;
                this.positions[i*3+1] = p.homeY + y;
                this.positions[i*3+2] = p.homeZ + localZ;

                if (p.threatEffect === "interference") {
                    this.positions[i*3] += (Math.random()-0.5)*2;
                    this.positions[i*3+1] += (Math.random()-0.5)*2;
                    this.positions[i*3+2] += (Math.random()-0.5)*2;
                    if(Math.random()>0.9) p.currentColor.setHex(0xffffff);
                    else p.currentColor.copy(p.baseColor);
                }
                
            } else if (p.state === "leaking") {
                this.positions[i*3] += p.leakVelocity.x;
                this.positions[i*3+1] += p.leakVelocity.y;
                this.positions[i*3+2] += p.leakVelocity.z;
                
                p.alpha -= 0.002;
                p.currentColor.lerp(new THREE.Color(0xff4444), 0.1);
                
                if (p.alpha < 0.05) {
                    p.state = "orbiting";
                    p.alpha = 0.3 + Math.random() * 0.6;
                    p.currentColor.copy(p.baseColor);
                }
            } else if (p.state === "vortex") {
                p.orbitRadius *= 0.98;
                p.orbitPhase += p.orbitSpeed * deltaTime * 3;
                
                this.positions[i*3] = p.homeX + Math.cos(p.orbitPhase) * p.orbitRadius;
                this.positions[i*3+1] = p.homeY + (this.positions[i*3+1] - p.homeY) * 0.9; 
                this.positions[i*3+2] = p.homeZ + Math.sin(p.orbitPhase) * p.orbitRadius;
                
                if (p.orbitRadius < 5) {
                    p.orbitRadius = 50 + Math.random() * 50;
                }
            }
            
            this.colors[i*3] = p.currentColor.r * p.alpha;
            this.colors[i*3+1] = p.currentColor.g * p.alpha;
            this.colors[i*3+2] = p.currentColor.b * p.alpha;
        }
        
        this.geometry.attributes.position.needsUpdate = true;
        this.geometry.attributes.color.needsUpdate = true;
    }
}
