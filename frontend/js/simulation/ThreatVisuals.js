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
                // Pre-allocate geometry to avoid memory leaks
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
                    intensity: intensity,
                    progress: 0.0 // Track expansion progress instead of reallocating
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

            case "campaign": {
                // Animated red arcs / lightning between correlated backends.
                // Creates multiple pulsing tube geometries radiating from the backend
                // to simulate coordinated attack connections.
                const triggeringThreats = (threatEvent.evidence && threatEvent.evidence.triggering_threats) || [];
                const arcCount = Math.max(3, Math.min(triggeringThreats.length + 2, 8));

                for (let i = 0; i < arcCount; i++) {
                    // Random outward direction for each arc
                    const theta = (i / arcCount) * Math.PI * 2 + Math.random() * 0.5;
                    const phi = (Math.random() - 0.5) * Math.PI * 0.6;
                    const arcLength = backend.radius * (2.5 + Math.random() * 2.0);

                    const endX = backend.position.x + Math.cos(theta) * Math.cos(phi) * arcLength;
                    const endY = backend.position.y + Math.sin(phi) * arcLength;
                    const endZ = backend.position.z + Math.sin(theta) * Math.cos(phi) * arcLength;

                    // Build a curved path (quadratic bezier for lightning arc)
                    const midX = (backend.position.x + endX) / 2 + (Math.random() - 0.5) * arcLength * 0.5;
                    const midY = (backend.position.y + endY) / 2 + (Math.random() - 0.5) * arcLength * 0.4;
                    const midZ = (backend.position.z + endZ) / 2 + (Math.random() - 0.5) * arcLength * 0.5;

                    const curve = new THREE.QuadraticBezierCurve3(
                        backend.position.clone(),
                        new THREE.Vector3(midX, midY, midZ),
                        new THREE.Vector3(endX, endY, endZ)
                    );

                    const tubeGeo = new THREE.TubeGeometry(curve, 24, 0.4 + intensity * 0.3, 6, false);
                    const tubeMat = new THREE.MeshBasicMaterial({
                        color: 0xff2222,
                        transparent: true,
                        opacity: 0.6 * intensity,
                        blending: THREE.AdditiveBlending
                    });
                    const tube = new THREE.Mesh(tubeGeo, tubeMat);
                    this.scene.add(tube);

                    // Small sphere at the arc endpoint for emphasis
                    const tipGeo = new THREE.SphereGeometry(1.2, 8, 8);
                    const tipMat = new THREE.MeshBasicMaterial({
                        color: 0xff4444,
                        transparent: true,
                        opacity: 0.7 * intensity,
                        blending: THREE.AdditiveBlending
                    });
                    const tip = new THREE.Mesh(tipGeo, tipMat);
                    tip.position.set(endX, endY, endZ);
                    this.scene.add(tip);

                    objects.push({
                        mesh: tube,
                        type: 'campaign_arc',
                        baseOpacity: 0.6 * intensity,
                        phaseOffset: i * (Math.PI * 2 / arcCount)
                    });
                    objects.push({
                        mesh: tip,
                        type: 'campaign_tip',
                        phaseOffset: i * (Math.PI * 2 / arcCount)
                    });
                }

                // Inner red core pulse on the backend itself
                const corePulseGeo = new THREE.SphereGeometry(backend.radius * 1.15, 32, 32);
                const corePulseMat = new THREE.MeshBasicMaterial({
                    color: 0xff1100,
                    transparent: true,
                    opacity: 0.15 * intensity,
                    blending: THREE.AdditiveBlending
                });
                const corePulse = new THREE.Mesh(corePulseGeo, corePulseMat);
                corePulse.position.copy(backend.position);
                this.scene.add(corePulse);
                objects.push({ mesh: corePulse, type: 'pulsing' });
                break;
            }
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
                    // Update progress and use scale instead of recreating geometry
                    obj.progress += deltaTime * 1.5; // Scale speed
                    if (obj.progress > 1.0) obj.progress = 0.0;
                    
                    // Scale from 1.0 to roughly 3x
                    const scale = 1.0 + (obj.progress * 2.0);
                    obj.mesh.scale.set(scale, scale, 1);
                    obj.mesh.material.opacity = (1.0 - obj.progress) * obj.intensity;
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
                else if (obj.type === 'campaign_arc') {
                    // Red pulsing opacity — creates lightning-like flicker
                    const pulse = Math.sin(time * 8 + (obj.phaseOffset || 0)) * 0.5 + 0.5;
                    obj.mesh.material.opacity = obj.baseOpacity * (0.3 + pulse * 0.7);
                }
                else if (obj.type === 'campaign_tip') {
                    const tipPulse = Math.sin(time * 6 + (obj.phaseOffset || 0)) * 0.5 + 0.5;
                    const tipScale = 0.8 + tipPulse * 0.4;
                    obj.mesh.scale.set(tipScale, tipScale, tipScale);
                    obj.mesh.material.opacity = 0.4 + tipPulse * 0.4;
                }
            });
        });
    }
}
