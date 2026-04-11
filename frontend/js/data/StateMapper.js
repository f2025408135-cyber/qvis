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
            
            // Simple interaction since camera is global-ish in main.js
            // This is a hacky fallback if camera isn't passed
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
                    
                    document.dispatchEvent(new CustomEvent('openThreatPanel', { 
                        detail: { backend: backend, threats: threats } 
                    }));
                }
            }
        });
    }
}
