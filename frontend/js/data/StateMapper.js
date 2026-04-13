import { appState } from '../state.js';
import { Backend } from '../simulation/Backend.js';

export class StateMapper {
    constructor() {
        this.previousEntanglements = new Set();
        this.interactionsSetup = false;
    }

    mapSnapshot(snapshot, backendsMap, scene, particleSystem, threatVisualManager, entanglementRenderer, hud) {
        try {
            // Defensive: ensure snapshot has expected structure
            if (!snapshot || !snapshot.backends || !Array.isArray(snapshot.backends)) {
                console.warn('[StateMapper] Invalid snapshot structure:', snapshot);
                return;
            }

            snapshot.backends.forEach((backendData, index) => {
                if (!backendData || !backendData.id) return;

                let backend = backendsMap.get(backendData.id);
                if (!backend) {
                    try {
                        backend = new Backend(backendData, scene, index, snapshot.backends.length);
                        backendsMap.set(backendData.id, backend);
                        particleSystem.spawnBackendParticles(backend);
                    } catch (e) {
                        console.error(`[StateMapper] Failed to create backend ${backendData.id}:`, e);
                        return;
                    }
                }

                try {
                    backend.setThreatLevel(backendData.threat_level);
                } catch (e) {
                    console.error(`[StateMapper] Failed to set threat level for ${backendData.id}:`, e);
                }
            });

            // Remove backends no longer in snapshot
            const activeIds = new Set(snapshot.backends.map(b => b.id));
            backendsMap.forEach((backend, id) => {
                if (!activeIds.has(id)) {
                    try {
                        scene.remove(backend.group);
                        particleSystem.clearThreatEffects(id);
                        if (threatVisualManager) threatVisualManager.clearEffect(backend);
                        backendsMap.delete(id);
                    } catch (e) {
                        console.warn(`[StateMapper] Failed to remove backend ${id}:`, e);
                    }
                }
            });

            const activeThreatsByBackend = new Map();

            if (snapshot.threats && Array.isArray(snapshot.threats)) {
                snapshot.threats.forEach(threat => {
                    if (!threat || !threat.backend_id) return;

                    if (!activeThreatsByBackend.has(threat.backend_id)) {
                        activeThreatsByBackend.set(threat.backend_id, []);
                    }
                    activeThreatsByBackend.get(threat.backend_id).push(threat);

                    const backend = backendsMap.get(threat.backend_id);
                    if (backend) {
                        try {
                            particleSystem.triggerThreatEffect(threat.backend_id, threat.visual_effect, threat.visual_intensity);
                            threatVisualManager.applyThreatEffect(backend, threat);
                        } catch (e) {
                            console.error(`[StateMapper] Failed to apply threat visual for ${threat.backend_id}:`, e);
                        }
                    }
                });
            }

            backendsMap.forEach((backend, id) => {
                if (!activeThreatsByBackend.has(id)) {
                    try {
                        particleSystem.clearThreatEffects(id);
                    } catch (e) {
                        console.warn(`[StateMapper] Failed to clear threats for ${id}:`, e);
                    }
                }
            });

            const currentEntanglements = new Set();

            if (snapshot.entanglement_pairs && Array.isArray(snapshot.entanglement_pairs)) {
                snapshot.entanglement_pairs.forEach(pair => {
                    if (!Array.isArray(pair) || pair.length < 2) return;

                    const idA = pair[0];
                    const idB = pair[1];
                    const pairKey = entanglementRenderer.getPairKey(idA, idB);
                    currentEntanglements.add(pairKey);

                    const backendA = backendsMap.get(idA);
                    const backendB = backendsMap.get(idB);

                    if (backendA && backendB) {
                        try {
                            entanglementRenderer.addEntanglement(backendA, backendB, 1.0);
                        } catch (e) {
                            console.error(`[StateMapper] Failed to add entanglement ${pairKey}:`, e);
                        }
                    }
                });
            }

            this.previousEntanglements.forEach(pairKey => {
                if (!currentEntanglements.has(pairKey)) {
                    const ids = pairKey.split('-');
                    if (ids.length === 2) {
                        const bA = backendsMap.get(ids[0]);
                        const bB = backendsMap.get(ids[1]);
                        if (bA && bB) {
                            try {
                                entanglementRenderer.removeEntanglement(bA, bB);
                            } catch (e) {
                                console.warn(`[StateMapper] Failed to remove entanglement ${pairKey}:`, e);
                            }
                        }
                    }
                }
            });

            this.previousEntanglements = currentEntanglements;

            if (hud) {
                try {
                    hud.update(snapshot);
                } catch (e) {
                    console.error('[StateMapper] HUD update failed:', e);
                }
            }

            this.setupInteractions(backendsMap, activeThreatsByBackend, scene);

        } catch (e) {
            console.error('[StateMapper] Critical error in mapSnapshot:', e);
        }
    }

    setupInteractions(backendsMap, activeThreatsByBackend, scene) {
        if (this.interactionsSetup) return;
        this.interactionsSetup = true;

        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();

        window.addEventListener('click', (event) => {
            if (event.target.id !== 'qvis-canvas') return;

            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

            if (appState.camera) {
                raycaster.setFromCamera(mouse, appState.camera);

                const objectsToIntersect = [];
                const meshToBackendId = new Map();

                backendsMap.forEach((backend, id) => {
                    if (backend.core) {
                        objectsToIntersect.push(backend.core);
                        meshToBackendId.set(backend.core.uuid, id);
                    }
                });

                const intersects = raycaster.intersectObjects(objectsToIntersect);

                if (intersects.length > 0) {
                    const hitUuid = intersects[0].object.uuid;
                    const backendId = meshToBackendId.get(hitUuid);
                    const backend = backendsMap.get(backendId);
                    const threats = activeThreatsByBackend.get(backendId) || [];

                    if (backend) {
                        this.flyToBackend(backend);
                        document.dispatchEvent(new CustomEvent('openThreatPanel', {
                            detail: { backend: backend, threats: threats }
                        }));
                    }
                } else {
                    this.resetCamera();
                    // Close threat panel — fixed: was using dead __vue__ reference
                    const panel = document.getElementById('threat-panel');
                    if (panel && panel.classList) {
                        panel.classList.remove('open');
                        panel.style.transform = 'translateX(100%)';
                    }
                }
            }
        });

        document.addEventListener('openThreatPanel', (e) => {
            if (e.detail && e.detail.threat && e.detail.threat.backend_id) {
                const backend = backendsMap.get(e.detail.threat.backend_id);
                if (backend) {
                    this.flyToBackend(backend);
                }
            }
        });
    }

    flyToBackend(backend) {
        if (!backend || !backend.position) return;
        if (!window.TWEEN || !appState.camera || !appState.controls) {
            // Fallback: instant snap
            if (appState.camera && backend.position) {
                appState.camera.position.set(
                    backend.position.x - 80,
                    backend.position.y + 40,
                    backend.position.z + 120
                );
                appState.camera.lookAt(backend.position);
            }
            return;
        }

        appState.isAnimatingCamera = true;

        const targetPos = backend.position.clone();

        new TWEEN.Tween(appState.controls.target)
            .to({ x: targetPos.x, y: targetPos.y, z: targetPos.z }, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .start();

        const offset = new THREE.Vector3(targetPos.x - 80, targetPos.y + 40, targetPos.z + 120);

        new TWEEN.Tween(appState.camera.position)
            .to({ x: offset.x, y: offset.y, z: offset.z }, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .onUpdate(() => {
                appState.camera.lookAt(appState.controls.target);
            })
            .onComplete(() => {
                appState.isAnimatingCamera = false;
                appState.controls.radius = appState.camera.position.distanceTo(appState.controls.target);

                const dir = new THREE.Vector3().subVectors(appState.camera.position, appState.controls.target).normalize();
                appState.controls.phi = Math.acos(dir.y);
                appState.controls.theta = Math.atan2(dir.z, dir.x);
            })
            .start();
    }

    resetCamera() {
        if (!appState.camera || !appState.controls) return;
        if (!window.TWEEN) {
            // Fallback: instant reset
            appState.camera.position.set(0, 0, 600);
            appState.camera.lookAt(0, 0, 0);
            appState.controls.radius = 600;
            appState.controls.phi = Math.PI / 2;
            appState.controls.theta = Math.PI / 2;
            return;
        }

        appState.isAnimatingCamera = true;

        new TWEEN.Tween(appState.controls.target)
            .to({ x: 0, y: 0, z: 0 }, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .start();

        new TWEEN.Tween(appState.camera.position)
            .to({ x: 0, y: 0, z: 600 }, 1500)
            .easing(TWEEN.Easing.Cubic.InOut)
            .onUpdate(() => {
                appState.camera.lookAt(appState.controls.target);
            })
            .onComplete(() => {
                appState.isAnimatingCamera = false;
                appState.controls.radius = 600;
                appState.controls.phi = Math.PI / 2;
                appState.controls.theta = Math.PI / 2;
            })
            .start();
    }
}
