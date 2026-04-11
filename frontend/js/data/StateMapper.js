import { Backend } from '../simulation/Backend.js';

export class StateMapper {
    constructor() {
        this.previousEntanglements = new Set();
    }

    mapSnapshot(snapshot, backendsMap, scene, particleSystem, threatVisualManager, entanglementRenderer, hud) {
        
        snapshot.backends.forEach((backendData, index) => {
            let backend = backendsMap.get(backendData.id);
            if (!backend) {
                backend = new Backend(backendData, scene, index, snapshot.backends.length);
                backendsMap.set(backendData.id, backend);
                
                particleSystem.spawnBackendParticles(backend);
            }
            
            backend.setThreatLevel(backendData.threat_level);
        });
        
        const activeThreatsByBackend = new Map();
        
        snapshot.threats.forEach(threat => {
            if (!threat.backend_id) return;
            
            if (!activeThreatsByBackend.has(threat.backend_id)) {
                activeThreatsByBackend.set(threat.backend_id, []);
            }
            activeThreatsByBackend.get(threat.backend_id).push(threat);
            
            const backend = backendsMap.get(threat.backend_id);
            if (backend) {
                particleSystem.triggerThreatEffect(threat.backend_id, threat.visual_effect, threat.visual_intensity);
                threatVisualManager.applyThreatEffect(backend, threat);
            }
        });
        
        backendsMap.forEach((backend, id) => {
            if (!activeThreatsByBackend.has(id)) {
                particleSystem.clearThreatEffects(id);
            }
        });
        
        const currentEntanglements = new Set();
        
        snapshot.entanglement_pairs.forEach(pair => {
            const idA = pair[0];
            const idB = pair[1];
            const pairKey = entanglementRenderer.getPairKey(idA, idB);
            currentEntanglements.add(pairKey);
            
            const backendA = backendsMap.get(idA);
            const backendB = backendsMap.get(idB);
            
            if (backendA && backendB) {
                entanglementRenderer.addEntanglement(backendA, backendB, 1.0);
            }
        });
        
        this.previousEntanglements.forEach(pairKey => {
            if (!currentEntanglements.has(pairKey)) {
                const ids = pairKey.split('-');
                if(ids.length === 2) {
                    const bA = backendsMap.get(ids[0]);
                    const bB = backendsMap.get(ids[1]);
                    if(bA && bB) entanglementRenderer.removeEntanglement(bA, bB);
                }
            }
        });
        
        this.previousEntanglements = currentEntanglements;
        
        hud.update(snapshot);
        
        this.setupInteractions(backendsMap, activeThreatsByBackend, scene);
    }
    
    setupInteractions(backendsMap, activeThreatsByBackend, scene) {
        if(this.interactionsSetup) return;
        this.interactionsSetup = true;
        
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();
        
        window.addEventListener('click', (event) => {
            if (event.target.id !== 'qvis-canvas') return;
            
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
            
            if(window.__camera) {
                raycaster.setFromCamera(mouse, window.__camera);
                
                const objectsToIntersect = [];
                const meshToBackendId = new Map();
                
                backendsMap.forEach((backend, id) => {
                    objectsToIntersect.push(backend.core);
                    meshToBackendId.set(backend.core.uuid, id);
                });
                
                const intersects = raycaster.intersectObjects(objectsToIntersect);
                
                if (intersects.length > 0) {
                    const hitUuid = intersects[0].object.uuid;
                    const backendId = meshToBackendId.get(hitUuid);
                    const backend = backendsMap.get(backendId);
                    const threats = activeThreatsByBackend.get(backendId) || [];
                    
                    // Trigger camera animation
                    this.flyToBackend(backend);
                    
                    document.dispatchEvent(new CustomEvent('openThreatPanel', { 
                        detail: { backend: backend, threats: threats } 
                    }));
                } else {
                    // Clicked on empty space
                    this.resetCamera();
                    document.getElementById('threat-panel').__vue__?.close();
                }
            }
        });

        // Also listen for clicking threat tags to fly to backend
        document.addEventListener('openThreatPanel', (e) => {
            if (e.detail.threat && e.detail.threat.backend_id) {
                const backend = backendsMap.get(e.detail.threat.backend_id);
                if (backend) {
                    this.flyToBackend(backend);
                }
            }
        });
    }

    flyToBackend(backend) {
        if (!window.TWEEN || !window.__camera || !window.__controls) return;
        
        window.__isAnimatingCamera = true;
        
        const targetPos = backend.position.clone();
        
        // Target looks at backend
        new TWEEN.Tween(window.__controls.target)
            .to({x: targetPos.x, y: targetPos.y, z: targetPos.z}, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .start();
            
        // Calculate offset position for camera (slightly to the left to leave room for panel)
        const offset = new THREE.Vector3(targetPos.x - 80, targetPos.y + 40, targetPos.z + 120);
        
        new TWEEN.Tween(window.__camera.position)
            .to({x: offset.x, y: offset.y, z: offset.z}, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .onUpdate(() => {
                window.__camera.lookAt(window.__controls.target);
            })
            .onComplete(() => {
                window.__isAnimatingCamera = false;
                // Sync spherical coords back to controls
                window.__controls.radius = window.__camera.position.distanceTo(window.__controls.target);
                
                const dir = new THREE.Vector3().subVectors(window.__camera.position, window.__controls.target).normalize();
                window.__controls.phi = Math.acos(dir.y);
                window.__controls.theta = Math.atan2(dir.z, dir.x);
            })
            .start();
    }

    resetCamera() {
        if (!window.TWEEN || !window.__camera || !window.__controls) return;
        
        window.__isAnimatingCamera = true;
        
        new TWEEN.Tween(window.__controls.target)
            .to({x: 0, y: 0, z: 0}, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .start();
            
        new TWEEN.Tween(window.__camera.position)
            .to({x: 0, y: 0, z: 600}, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .onUpdate(() => {
                window.__camera.lookAt(window.__controls.target);
            })
            .onComplete(() => {
                window.__isAnimatingCamera = false;
                window.__controls.radius = 600;
                window.__controls.phi = Math.PI / 2;
                window.__controls.theta = Math.PI / 2;
            })
            .start();
    }
}
