export class ThreatVisualManager {
    constructor(scene) {
        this.scene = scene;
        this.activeEffects = new Map();
    }

    applyThreatEffect(backend, threatEvent) {
        const effectName = threatEvent.visual_effect;
        const intensity = threatEvent.visual_intensity || 0.5;
        
        if (this.activeEffects.has(backend.id)) {
            if (this.activeEffects.get(backend.id).effectName === effectName) return;
            this.clearEffect(backend, this.activeEffects.get(backend.id).effectName);
        }

        const objects = [];
        
        switch (effectName) {
            case "timing_ring":
                const ringGeo = new THREE.RingGeometry(backend.radius * 1.2, backend.radius * 1.5, 32);
                const ringMat = new THREE.MeshBasicMaterial({
                    color: 0xff6622,
                    transparent: true,
                    opacity: 0.6 * intensity,
                    side: THREE.DoubleSide,
                    blending: THREE.AdditiveBlending
                });
                const ring = new THREE.Mesh(ringGeo, ringMat);
                ring.rotation.x = Math.PI / 2;
                ring.position.copy(backend.position);
                this.scene.add(ring);
                objects.push({
                    mesh: ring,
                    type: 'expanding_ring',
                    baseRadius: backend.radius * 1.2,
                    maxRadius: backend.radius * 3.5,
                    currentRadius: backend.radius * 1.2,
                    intensity: intensity
                });
                break;
                
            case "calibration_drain":
                const funnelGeo = new THREE.ConeGeometry(backend.radius * 1.5, backend.radius * 4, 8, 1, true);
                const funnelMat = new THREE.MeshBasicMaterial({
                    color: 0x44ff88,
                    wireframe: true,
                    transparent: true,
                    opacity: 0.3 + intensity * 0.4
                });
                const funnel = new THREE.Mesh(funnelGeo, funnelMat);
                funnel.position.copy(backend.position);
                funnel.position.y -= backend.radius * 2;
                funnel.rotation.x = Math.PI;
                this.scene.add(funnel);
                objects.push({ mesh: funnel, type: 'rotating_funnel' });
                break;
                
            case "vortex":
                const darkGeo = new THREE.SphereGeometry(backend.radius * 1.05, 32, 32);
                const darkMat = new THREE.MeshBasicMaterial({ color: 0x000000 });
                const darkSphere = new THREE.Mesh(darkGeo, darkMat);
                darkSphere.position.copy(backend.position);
                this.scene.add(darkSphere);
                
                const discGeo = new THREE.TorusGeometry(backend.radius * 1.8, backend.radius * 0.4, 2, 64);
                const discMat = new THREE.MeshBasicMaterial({
                    color: 0xff4400,
                    transparent: true,
                    opacity: 0.8
                });
                const disc = new THREE.Mesh(discGeo, discMat);
                disc.rotation.x = Math.PI / 2;
                disc.position.copy(backend.position);
                this.scene.add(disc);
                
                objects.push({ mesh: darkSphere, type: 'static' });
                objects.push({ mesh: disc, type: 'rotating_disc' });
                break;
                
            case "particle_leak":
                const breachGeo = new THREE.SphereGeometry(backend.radius * 0.5, 16, 16);
                const breachMat = new THREE.MeshBasicMaterial({
                    color: 0xff3333,
                    transparent: true,
                    opacity: 0.8,
                    blending: THREE.AdditiveBlending
                });
                const breach = new THREE.Mesh(breachGeo, breachMat);
                breach.position.copy(backend.position);
                breach.position.x += backend.radius * 0.8;
                this.scene.add(breach);
                objects.push({ mesh: breach, type: 'pulsing' });
                break;
                
            case "interference":
                const lineGeo = new THREE.BufferGeometry();
                const linePoints = [];
                for(let i=0; i<50 * intensity; i++) {
                    linePoints.push(
                        (Math.random()-0.5)*backend.radius*3,
                        (Math.random()-0.5)*backend.radius*3,
                        (Math.random()-0.5)*backend.radius*3
                    );
                    linePoints.push(
                        (Math.random()-0.5)*backend.radius*3,
                        (Math.random()-0.5)*backend.radius*3,
                        (Math.random()-0.5)*backend.radius*3
                    );
                }
                lineGeo.setAttribute('position', new THREE.Float32BufferAttribute(linePoints, 3));
                const lineMat = new THREE.LineBasicMaterial({
                    color: 0xffffff, transparent: true, opacity: 0.5
                });
                const lines = new THREE.LineSegments(lineGeo, lineMat);
                lines.position.copy(backend.position);
                this.scene.add(lines);
                objects.push({ mesh: lines, type: 'static', rawGeo: lineGeo, rad: backend.radius });
                break;
                
            case "color_bleed":
                const haloGeo = new THREE.SphereGeometry(backend.radius * 2.5, 32, 32);
                const haloMat = new THREE.MeshBasicMaterial({
                    color: 0xffaa00,
                    transparent: true,
                    opacity: 0.08,
                    blending: THREE.AdditiveBlending
                });
                const halo = new THREE.Mesh(haloGeo, haloMat);
                halo.position.copy(backend.position);
                this.scene.add(halo);
                objects.push({ mesh: halo, type: 'pulsing_scale' });
                break;
        }

        this.activeEffects.set(backend.id, { effectName, objects });
    }

    clearEffect(backend, effectName) {
        if (!this.activeEffects.has(backend.id)) return;
        
        const data = this.activeEffects.get(backend.id);
        
        data.objects.forEach(obj => {
            obj.mesh.geometry.dispose();
            obj.mesh.material.dispose();
            this.scene.remove(obj.mesh);
        });
        
        this.activeEffects.delete(backend.id);
    }

    update(deltaTime) {
        const time = performance.now() * 0.001;
        
        this.activeEffects.forEach((data, backendId) => {
            data.objects.forEach(obj => {
                if (obj.type === 'expanding_ring') {
                    obj.currentRadius += deltaTime * 50;
                    if (obj.currentRadius > obj.maxRadius) {
                        obj.currentRadius = obj.baseRadius;
                    }
                    obj.mesh.geometry.dispose();
                    obj.mesh.geometry = new THREE.RingGeometry(obj.currentRadius, obj.currentRadius + 5, 32);
                    obj.mesh.material.opacity = (1.0 - (obj.currentRadius - obj.baseRadius) / (obj.maxRadius - obj.baseRadius)) * obj.intensity;
                } 
                else if (obj.type === 'rotating_funnel') {
                    obj.mesh.rotation.y += deltaTime * 2;
                }
                else if (obj.type === 'rotating_disc') {
                    obj.mesh.rotation.z += deltaTime * 2;
                }
                else if (obj.type === 'pulsing') {
                    obj.mesh.material.opacity = 0.5 + Math.sin(time * 10) * 0.3;
                }
                else if (obj.type === 'pulsing_scale') {
                    const s = 0.95 + Math.sin(time * 3) * 0.05;
                    obj.mesh.scale.set(s, s, s);
                }
            });
        });
    }
}
