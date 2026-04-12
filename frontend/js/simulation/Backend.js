export class Backend {
    constructor(backendData, scene, index, totalBackends) {
        this.id = backendData.id;
        this.scene = scene;
        this.num_qubits = backendData.num_qubits;
        
        this.baseColor = this.getColorForPlatform(backendData.platform, backendData.is_simulator);
        this.radius = Math.sqrt(this.num_qubits) * 1.8;
        
        this.group = new THREE.Group();
        
        const geometry = new THREE.SphereGeometry(this.radius, 32, 32);
        this.material = new THREE.MeshPhongMaterial({
            color: this.baseColor,
            emissive: this.baseColor,
            emissiveIntensity: 0.3,
            shininess: 60
        });
        this.core = new THREE.Mesh(geometry, this.material);
        this.group.add(this.core);

        const glowGeo = new THREE.TorusGeometry(this.radius * 1.4, 0.8, 8, 64);
        this.glowMat = new THREE.MeshBasicMaterial({
            color: this.baseColor,
            transparent: true,
            opacity: 0.3
        });
        this.glowRing = new THREE.Mesh(glowGeo, this.glowMat);
        this.glowRing.rotation.x = Math.PI / 2;
        this.group.add(this.glowRing);

        const ring1Geo = new THREE.TorusGeometry(this.radius * 2.0, 0.2, 8, 64);
        const ringMat = new THREE.MeshBasicMaterial({
            color: 0xffffff,
            transparent: true,
            opacity: 0.08,
            wireframe: false
        });
        this.orbitRing1 = new THREE.Mesh(ring1Geo, ringMat);
        this.orbitRing1.rotation.x = Math.PI / 6;
        this.group.add(this.orbitRing1);

        const ring2Geo = new THREE.TorusGeometry(this.radius * 2.8, 0.2, 8, 64);
        this.orbitRing2 = new THREE.Mesh(ring2Geo, ringMat);
        this.orbitRing2.rotation.z = Math.PI / 6;
        this.group.add(this.orbitRing2);

        const canvas = document.createElement('canvas');
        canvas.width = 256;
        canvas.height = 64;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = 'rgba(0,0,0,0.5)';
        ctx.fillRect(0,0,256,64);
        ctx.font = '24px monospace';
        ctx.fillStyle = 'white';
        ctx.textAlign = 'center';
        ctx.fillText(backendData.name, 128, 40);
        
        const texture = new THREE.CanvasTexture(canvas);
        const spriteMat = new THREE.SpriteMaterial({ map: texture });
        this.label = new THREE.Sprite(spriteMat);
        this.label.scale.set(80, 20, 1);
        this.label.position.y = -this.radius - 20;
        this.group.add(this.label);

        // Deterministic layout instead of random Y
        const angle = (index / Math.max(totalBackends, 1)) * Math.PI * 2;
        const layoutRadius = 150;
        this.group.position.set(
            Math.cos(angle) * layoutRadius,
            (index % 2 === 0 ? 25 : -25), // Staggered deterministic Y
            Math.sin(angle) * layoutRadius
        );
        this.position = this.group.position.clone();
        
        this.scene.add(this.group);
        this.setThreatLevel(backendData.threat_level || 'none');
    }

    getColorForPlatform(platform, is_simulator) {
        if (is_simulator) return 0x335577;
        switch(platform) {
            case 'ibm_quantum': return 0x2255bb;
            case 'amazon_braket': return 0x22aaff;
            case 'azure_quantum': return 0x0078d4;
            default: return 0x555555;
        }
    }

    setThreatLevel(severity) {
        this.threatLevel = severity;
        const color = new THREE.Color(this.baseColor);
        let emissiveColor = new THREE.Color(this.baseColor);
        let intensity = 0.3;

        switch(severity) {
            case 'low':
                emissiveColor.lerp(new THREE.Color(0x225522), 0.5);
                break;
            case 'medium':
                emissiveColor.lerp(new THREE.Color(0x886600), 0.7);
                intensity = 0.5;
                break;
            case 'high':
                emissiveColor.lerp(new THREE.Color(0x883300), 0.9);
                intensity = 0.7;
                break;
            case 'critical':
                emissiveColor.setHex(0xaa1100);
                intensity = 0.9;
                break;
        }

        this.material.emissive = emissiveColor;
        this.material.emissiveIntensity = intensity;
    }

    update(deltaTime, totalTime) {
        this.core.rotation.y += 0.003;
        this.glowMat.opacity = 0.2 + Math.sin(totalTime * 2.0) * 0.1;
        this.orbitRing1.rotation.y -= 0.001;
        this.orbitRing2.rotation.y += 0.002;
    }
}
