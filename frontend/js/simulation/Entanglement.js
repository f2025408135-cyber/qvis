export class EntanglementRenderer {
    constructor(scene) {
        this.scene = scene;
        this.threads = new Map();
    }

    getPairKey(idA, idB) {
        return [idA, idB].sort().join('-');
    }

    addEntanglement(backendA, backendB, strength = 1.0) {
        const pairKey = this.getPairKey(backendA.id, backendB.id);
        
        if (this.threads.has(pairKey)) return;

        const start = backendA.position;
        const end = backendB.position;
        
        const dist = start.distanceTo(end);
        const midPoint = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5);
        
        midPoint.y += dist * 0.3 + 20;
        
        const points = [
            start,
            new THREE.Vector3().lerpVectors(start, midPoint, 0.5).add(new THREE.Vector3(0, dist*0.1, 0)),
            midPoint,
            new THREE.Vector3().lerpVectors(midPoint, end, 0.5).add(new THREE.Vector3(0, dist*0.1, 0)),
            end
        ];
        
        const curve = new THREE.CatmullRomCurve3(points);
        
        const geometry = new THREE.TubeGeometry(curve, 64, 0.4, 8, false);
        const material = new THREE.MeshBasicMaterial({
            color: 0x40d8a0,
            transparent: true,
            opacity: 0.25 * strength,
            blending: THREE.AdditiveBlending
        });
        
        const mesh = new THREE.Mesh(geometry, material);
        this.scene.add(mesh);
        
        const particles = [];
        const numParticles = 3 + Math.floor(Math.random() * 3);
        
        const particleGeo = new THREE.SphereGeometry(1.5, 8, 8);
        const particleMat = new THREE.MeshBasicMaterial({
            color: 0x80ffcc,
            transparent: true,
            opacity: 0.8
        });
        
        for (let i = 0; i < numParticles; i++) {
            const pMesh = new THREE.Mesh(particleGeo, particleMat);
            this.scene.add(pMesh);
            particles.push({
                mesh: pMesh,
                progress: i / numParticles,
                speed: 0.2 + Math.random() * 0.15
            });
        }
        
        this.threads.set(pairKey, { curve, mesh, particles, material, opacity: material.opacity });
    }

    update(deltaTime) {
        this.threads.forEach((thread) => {
            thread.particles.forEach(p => {
                p.progress += p.speed * deltaTime;
                if (p.progress >= 1.0) p.progress = 0;
                
                const point = thread.curve.getPoint(p.progress);
                p.mesh.position.copy(point);
                
                const scale = Math.sin(p.progress * Math.PI) * 1.5 + 0.5;
                p.mesh.scale.set(scale, scale, scale);
            });
            
            const time = performance.now() * 0.001;
            thread.material.opacity = thread.opacity * (0.8 + Math.sin(time * 3) * 0.2);
        });
    }

    removeEntanglement(backendA, backendB) {
        const pairKey = this.getPairKey(backendA.id, backendB.id);
        const thread = this.threads.get(pairKey);
        
        if (thread) {
            thread.mesh.geometry.dispose();
            thread.material.dispose();
            this.scene.remove(thread.mesh);
            
            thread.particles.forEach(p => {
                p.mesh.geometry.dispose();
                p.mesh.material.dispose();
                this.scene.remove(p.mesh);
            });
            
            this.threads.delete(pairKey);
        }
    }
}
