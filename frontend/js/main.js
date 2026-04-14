/**
 * QVis — Quantum Threat Topology Engine
 * Main entry point with robust initialization and fallback handling.
 */

import { appState } from './state.js';
import { ParticleSystem } from './simulation/ParticleSystem.js';
import { Backend } from './simulation/Backend.js';
import { Controls } from './ui/Controls.js';
import { WSClient, WS_STATE } from './data/WSClient.js';
import { StateMapper } from './data/StateMapper.js';
import { EntanglementRenderer } from './simulation/Entanglement.js';
import { ThreatVisualManager } from './simulation/ThreatVisuals.js';
import { HUD } from './ui/HUD.js';
import { ThreatPanel } from './ui/ThreatPanel.js';
import { Legend } from './ui/Legend.js';
import { Timeline } from './ui/Timeline.js';
import { FallbackManager, FALLBACK_STATE } from './core/FallbackManager.js';
import { toastManager } from './core/ToastManager.js';
import { perfMonitor } from './core/PerformanceMonitor.js';
import { Canvas2DFallback } from './renderers/Canvas2DFallback.js';
import { AudioEngine } from './core/AudioEngine.js';

let scene, camera, renderer, composer, starSystem;
let lastTime = 0;
let controls;
let backends = new Map();
let particleSystem;
let threatVisualManager;
let entanglementRenderer;
let stateMapper;
let hud, threatPanel, legend, timeline;
let canvas2d = null;
let useWebGL = true;
const audioEngine = new AudioEngine();

// ─── Loading State Machine ───────────────────────────────────────────
const LOADING_STAGES = {
    DETECTING: { text: 'DETECTING CAPABILITIES...', progress: 0 },
    LOADING_SCRIPTS: { text: 'VALIDATING RENDERER...', progress: 15 },
    INITIALIZING: { text: 'INITIALIZING QUANTUM STATE...', progress: 30 },
    CONNECTING: { text: 'CONNECTING TO TELEMETRY...', progress: 60 },
    RECEIVING: { text: 'RECEIVING FIRST TELEMETRY...', progress: 85 },
    READY: { text: 'QUANTUM STATE INITIALIZED', progress: 100 }
};

function updateLoadingStage(stage) {
    const loadingEl = document.getElementById('loading');
    if (!loadingEl) return;

    const textEl = loadingEl.querySelector('.loader-text');
    const progressEl = loadingEl.querySelector('.loader-progress-fill');
    const percentEl = loadingEl.querySelector('.loader-progress-text');

    if (textEl) textEl.textContent = stage.text;
    if (progressEl) progressEl.style.width = stage.progress + '%';
    if (percentEl) percentEl.textContent = stage.progress + '%';
}

function hideLoading() {
    const loadingEl = document.getElementById('loading');
    if (loadingEl) {
        loadingEl.classList.add('loader-exit');
        setTimeout(() => { loadingEl.style.display = 'none'; }, 600);
    }
}

// ─── Initialization ──────────────────────────────────────────────────

function bootstrap() {
    try {
        // Stage 1: Detect capabilities
        updateLoadingStage(LOADING_STAGES.DETECTING);
        const fallbackManager = new FallbackManager();
        fallbackManager.installGlobalHandlers();
        const state = fallbackManager.detectCapabilities();

        // Register fallback error listeners
        fallbackManager.on('uncaughtError', (data) => {
            toastManager.error(`Runtime error: ${data.message}`);
        });
        fallbackManager.on('unhandledRejection', (data) => {
            toastManager.warning('Async operation failed — system continuing');
        });
        fallbackManager.on('networkChange', (data) => {
            if (!data.online) {
                toastManager.warning('Network connection lost — operating in offline mode', 6000);
            } else {
                toastManager.success('Network connection restored', 3000);
            }
        });

        // Stage 2: Validate scripts
        updateLoadingStage(LOADING_STAGES.LOADING_SCRIPTS);
        const scriptErrors = fallbackManager.validateCriticalScripts();

        if (state === FALLBACK_STATE.CRITICAL) {
            showCriticalError(fallbackManager);
            return;
        }

        if (state === FALLBACK_STATE.FALLBACK_2D || scriptErrors.length > 0) {
            useWebGL = false;
            if (scriptErrors.length > 0) {
                scriptErrors.forEach(err => console.warn('[QVis]', err));
                toastManager.warning('WebGL unavailable — running in 2D fallback mode', 6000);
            }
        }

        // Stage 3: Initialize
        updateLoadingStage(LOADING_STAGES.INITIALIZING);

        if (useWebGL) {
            initThreeJS(fallbackManager);
        } else {
            initCanvas2D(fallbackManager);
        }

        // Initialize UI components (work in both modes)
        hud = new HUD(document.getElementById('hud'));
        threatPanel = new ThreatPanel(document.getElementById('threat-panel'));
        legend = new Legend(document.getElementById('legend'));
        timeline = new Timeline(document.getElementById('timeline'));

        // Initialize performance monitor
        perfMonitor.init();

        // Backend detail overlay
        initBackendDetailOverlay();

        // Stage 4: Connect WebSocket
        updateLoadingStage(LOADING_STAGES.CONNECTING);
        initWebSocket(fallbackManager);

        // Setup keyboard shortcuts
        initKeyboardShortcuts();

        // Initialize audio engine on first user interaction (browser autoplay policy)
        const initAudio = () => {
            audioEngine.init();
            document.removeEventListener('click', initAudio);
            document.removeEventListener('keydown', initAudio);
        };
        document.addEventListener('click', initAudio);
        document.addEventListener('keydown', initAudio);

    } catch (e) {
        console.error('[QVis] Bootstrap failed:', e);
        showCriticalError(null, e.message);
    }
}

function initThreeJS(fallbackManager) {
    try {
        const canvas = document.getElementById('qvis-canvas');
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x020408);
        scene.fog = new THREE.FogExp2(0x020408, 0.0015);

        camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 3000);
        camera.position.set(0, 0, 600);
        appState.camera = camera;

        renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: false });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.toneMapping = THREE.ReinhardToneMapping;
        renderer.toneMappingExposure = 1.5;

        // Post-processing (bloom) — graceful fallback if unavailable
        try {
            const renderScene = new THREE.RenderPass(scene, camera);

            const bloomPass = new THREE.UnrealBloomPass(
                new THREE.Vector2(window.innerWidth, window.innerHeight),
                1.5, 0.4, 0.1
            );

            composer = new THREE.EffectComposer(renderer);
            composer.addPass(renderScene);
            composer.addPass(bloomPass);
        } catch (e) {
            console.warn('[QVis] Post-processing init failed — using standard rendering:', e);
            composer = null;
        }

        // Lighting
        const ambientLight = new THREE.AmbientLight(0x0a0a20, 1.2);
        scene.add(ambientLight);

        const light1 = new THREE.PointLight(0x2244aa, 2.0);
        light1.position.set(300, 200, 200);
        scene.add(light1);

        const light2 = new THREE.PointLight(0x113355, 1.5);
        light2.position.set(-300, -200, 300);
        scene.add(light2);

        const light3 = new THREE.PointLight(0x001133, 1.0);
        light3.position.set(0, 300, -200);
        scene.add(light3);

        createStarField();

        const gridHelper = new THREE.GridHelper(2000, 50, 0x112244, 0x050a14);
        gridHelper.position.y = -250;
        scene.add(gridHelper);

        particleSystem = new ParticleSystem(scene);
        threatVisualManager = new ThreatVisualManager(scene);
        entanglementRenderer = new EntanglementRenderer(scene);

        controls = new Controls(camera, canvas);
        appState.controls = controls;

        stateMapper = new StateMapper();

        window.addEventListener('resize', onWindowResize);
        requestAnimationFrame(animateWebGL);

        console.log('[QVis] Three.js initialized successfully');

    } catch (e) {
        console.error('[QVis] Three.js initialization failed — falling back to 2D:', e);
        toastManager.error('3D rendering failed — switching to 2D mode');
        useWebGL = false;
        initCanvas2D(fallbackManager);
    }
}

function initCanvas2D(fallbackManager) {
    try {
        const canvas = document.getElementById('qvis-canvas');
        canvas2d = new Canvas2DFallback(canvas);
        canvas2d.start();
        stateMapper = null; // Canvas2D handles its own mapping
        console.log('[QVis] Canvas 2D fallback initialized');
    } catch (e) {
        console.error('[QVis] Canvas 2D fallback also failed:', e);
        showCriticalError(fallbackManager, 'All rendering modes failed');
    }
}

function initWebSocket(fallbackManager) {
    const backendHost = location.port === '3000' ? '127.0.0.1:8000' : (location.host || '127.0.0.1:8000');
    const wsToken = window.__QVIS_WS_TOKEN || '';
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${backendHost}/ws/simulation${wsToken ? '?token=' + wsToken : ''}`;
    let firstSnapshotReceived = false;

    const wsClient = new WSClient(wsUrl, (snapshot) => {
        // Cache for offline use
        fallbackManager.cacheSnapshot(snapshot);

        if (!firstSnapshotReceived) {
            firstSnapshotReceived = true;
            updateLoadingStage(LOADING_STAGES.READY);
            setTimeout(hideLoading, 300);
        }

        // Route to appropriate renderer
        if (useWebGL && stateMapper) {
            stateMapper.mapSnapshot(
                snapshot,
                backends,
                scene,
                particleSystem,
                threatVisualManager,
                entanglementRenderer,
                hud
            );
        } else if (canvas2d) {
            canvas2d.updateData(snapshot);
        }

        // Notify UI components of snapshot update
        document.dispatchEvent(new CustomEvent('snapshotUpdate', {
            detail: snapshot
        }));

        // Play audio cues for new threats
        if (snapshot.threats && snapshot.threats.length > 0) {
            const hasCritical = snapshot.threats.some(t => t.severity === 'critical');
            const hasHigh = snapshot.threats.some(t => t.severity === 'high');
            if (hasCritical) {
                audioEngine.playAlert();
            } else if (hasHigh) {
                audioEngine.playConnect();
            }
        }
    });

    // Connection state changes
    document.addEventListener('wsStateChange', (e) => {
        const { newState, attempt } = e.detail;

        if (newState === WS_STATE.RECONNECTING && attempt === 1) {
            toastManager.warning('Connection lost — attempting to reconnect...', 5000);
        } else if (newState === WS_STATE.OFFLINE) {
            toastManager.error('Unable to reconnect — displaying cached data', 8000);

            // Serve cached data to Canvas2D if in fallback mode
            const cached = fallbackManager.getLastKnownSnapshot();
            if (cached && canvas2d) {
                canvas2d.updateData(cached);
            }
        } else if (newState === WS_STATE.CONNECTED && attempt > 0) {
            toastManager.success('Connection restored', 3000);
        }
    });

    wsClient.connect();

    // Store reference for keyboard shortcut (reconnect)
    appState.wsClient = wsClient;
}

// ─── Three.js Rendering ──────────────────────────────────────────────

function createStarField() {
    const geometry = new THREE.BufferGeometry();
    const vertices = [];
    const sizes = [];

    for (let i = 0; i < 3000; i++) {
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        const radius = 1000 + Math.random() * 1000;

        const x = radius * Math.sin(phi) * Math.cos(theta);
        const y = radius * Math.sin(phi) * Math.sin(theta);
        const z = radius * Math.cos(phi);

        vertices.push(x, y, z);
        sizes.push(Math.random() * 2);
    }

    geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
    geometry.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));

    const material = new THREE.ShaderMaterial({
        uniforms: { time: { value: 0 } },
        vertexShader: `
            attribute float size;
            varying float vSize;
            uniform float time;
            void main() {
                vSize = size;
                vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
                gl_PointSize = size * (300.0 / -mvPosition.z) * (1.0 + 0.5 * sin(time + position.x));
                gl_Position = projectionMatrix * mvPosition;
            }
        `,
        fragmentShader: `
            void main() {
                vec2 xy = gl_PointCoord.xy - vec2(0.5);
                float ll = length(xy);
                if (ll > 0.5) discard;
                float alpha = (0.5 - ll) * 2.0;
                gl_FragColor = vec4(0.6, 0.8, 1.0, alpha * 0.7);
            }
        `,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false
    });

    starSystem = new THREE.Points(geometry, material);
    scene.add(starSystem);
}

function onWindowResize() {
    if (camera) {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
    }
    if (renderer) renderer.setSize(window.innerWidth, window.innerHeight);
    if (composer) composer.setSize(window.innerWidth, window.innerHeight);
    if (canvas2d) canvas2d.resize();
}

function animateWebGL(time) {
    requestAnimationFrame(animateWebGL);

    perfMonitor.beginFrame();

    if (window.TWEEN) window.TWEEN.update(time);

    time *= 0.001;
    const deltaTime = time - lastTime;
    lastTime = time;

    // Clamp deltaTime to avoid spiral of death after tab switch
    const clampedDelta = Math.min(deltaTime, 0.1);

    if (starSystem) {
        starSystem.rotation.y += 0.00003;
        starSystem.material.uniforms.time.value = time * 2.0;
    }

    if (controls && !appState.isAnimatingCamera) controls.update();

    backends.forEach(backend => {
        try { backend.update(clampedDelta, time); } catch (e) { /* skip */ }
    });
    if (particleSystem) particleSystem.update(clampedDelta);
    if (threatVisualManager) threatVisualManager.update(clampedDelta);
    if (entanglementRenderer) entanglementRenderer.update(clampedDelta);

    if (composer) {
        composer.render();
    } else if (renderer) {
        renderer.render(scene, camera);
    }

    perfMonitor.endFrame();
    if (perfMonitor.enabled && renderer) {
        perfMonitor.updateRendererInfo(renderer);
    }
}

// ─── Keyboard Shortcuts ──────────────────────────────────────────────

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Don't trigger shortcuts when typing in inputs
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

        switch (e.key) {
            case 'Escape':
                // Close threat panel
                const panel = document.getElementById('threat-panel');
                if (panel) {
                    panel.style.transform = 'translateX(100%)';
                    panel.classList.remove('open');
                }
                // Reset camera
                if (stateMapper) stateMapper.resetCamera();
                break;

            case 'r':
            case 'R':
                // Reset camera view
                if (stateMapper) stateMapper.resetCamera();
                toastManager.info('Camera reset');
                break;

            case ' ':
                // Pause/resume auto-rotate (toggle idle rotation)
                e.preventDefault();
                if (controls) {
                    controls.idleRotationPaused = !controls.idleRotationPaused;
                    toastManager.info(controls.idleRotationPaused ? 'Auto-rotate paused' : 'Auto-rotate enabled');
                }
                break;

            case '+':
            case '=':
                // Zoom in
                if (controls) controls.radius = Math.max(100, controls.radius - 50);
                break;

            case '-':
            case '_':
                // Zoom out
                if (controls) controls.radius = Math.min(2000, controls.radius + 50);
                break;

            case 'f':
            case 'F':
                // Toggle FPS counter
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    const enabled = perfMonitor.toggle();
                    toastManager.info(enabled ? 'Performance monitor enabled' : 'Performance monitor disabled');
                }
                break;

            case 'd':
            case 'D':
                // Toggle diagnostics report (DEF CON feature)
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    const fm = new FallbackManager();
                    const report = fm.getDiagnosticReport();
                    console.table(report);
                    toastManager.info('Diagnostic report logged to console (Ctrl+Shift+I)');
                }
                break;

            case 'h':
            case 'H':
                // Toggle HUD
                const hudEl = document.getElementById('hud');
                if (hudEl) {
                    hudEl.style.opacity = hudEl.style.opacity === '0' ? '1' : '0';
                }
                break;

            case 'm':
            case 'M':
                // Toggle audio
                const audioState = audioEngine.toggle();
                toastManager.info(audioState ? 'Audio enabled' : 'Audio muted');
                break;

            case '?':
                // Show keyboard shortcuts help
                toastManager.info('ESC: Close panel | R: Reset | Space: Pause rotate | +/-: Zoom | M: Mute | Ctrl+F: FPS | H: Toggle HUD', 8000);
                break;
        }
    });
}

// ─── HTML Escaping (XSS prevention) ─────────────────────────────────────
function _escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ─── Backend Detail Overlay ─────────────────────────────────────

function initBackendDetailOverlay() {
    // Create overlay container if it doesn't exist
    let overlay = document.getElementById('backend-detail-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'backend-detail-overlay';
        overlay.style.cssText = `
            display: none;
            position: fixed;
            top: 80px;
            left: 20px;
            z-index: 150;
            background: rgba(10, 10, 20, 0.92);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 6px;
            padding: 20px 24px;
            color: #e0e0e0;
            font-family: monospace;
            font-size: 12px;
            line-height: 1.6;
            min-width: 280px;
            max-width: 360px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            pointer-events: auto;
        `;
        document.body.appendChild(overlay);
    }

    // Create close button
    const closeBtn = document.createElement('div');
    closeBtn.id = 'backend-detail-close';
    closeBtn.textContent = '✕';
    closeBtn.style.cssText = `
        position: absolute; top: 8px; right: 12px; cursor: pointer;
        color: #667; font-size: 16px;
    `;
    overlay.appendChild(closeBtn);

    // Close on click
    closeBtn.addEventListener('click', () => { overlay.style.display = 'none'; });

    // Create content area
    const content = document.createElement('div');
    content.id = 'backend-detail-content';
    overlay.appendChild(content);

    // Listen for backendSelected events
    document.addEventListener('backendSelected', (e) => {
        const { backend, threats } = e.detail;
        if (!backend) return;

        const b = backend;
        const platformColor = Backend.getPlatformColor(b.platform);
        const hexColor = '#' + platformColor.toString(16).padStart(6, '0');

        // Format calibration summary
        let calSummary = 'N/A';
        if (b.calibration && b.calibration.length > 0) {
            const c = b.calibration[0];
            calSummary = `T1: ${c.t1_us ? c.t1_us.toFixed(1) : '?'}µs | T2: ${c.t2_us ? c.t2_us.toFixed(1) : '?'}µs | RO Err: ${c.readout_error !== undefined ? (c.readout_error * 100).toFixed(2) + '%' : '?'}`;
        }

        // Threat summary
        const threatCount = (threats || []).length;
        const threatList = (threats || []).slice(0, 5).map(t => {
            const sevColor = { critical: '#ff3333', high: '#ff7722', medium: '#ffbb00', low: '#33cc66', info: '#4488cc' }[t.severity] || '#888';
            return `<div style="display:flex;gap:6px;align-items:center;"><span style="color:${sevColor};">●</span> <span style="color:#aaa;font-size:10px;">${_escHtml(t.technique_id)}</span></div>`;
        }).join('');

        content.innerHTML = `
            <div style="margin-bottom:12px;">
                <div style="font-size:14px;font-weight:bold;color:#fff;margin-bottom:2px;">${_escHtml(b.name || b.id)}</div>
                <div style="font-size:10px;color:#667;letter-spacing:1px;">${_escHtml(b.platform || 'unknown')}${b.is_simulator ? ' (SIMULATOR)' : ''}</div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
                <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${hexColor};box-shadow:0 0 8px ${hexColor}44;"></span>
                <span style="color:${hexColor};font-size:11px;">${_escHtml(b.platform === 'ibm_quantum' ? 'IBM Quantum' : b.platform === 'amazon_braket' ? 'Amazon Braket' : b.platform === 'azure_quantum' ? 'Azure Quantum' : b.platform)}</span>
            </div>
            <table style="width:100%;border-collapse:collapse;margin-bottom:12px;">
                <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                    <td style="padding:3px 8px 3px 0;color:#667;">Qubits</td>
                    <td style="color:#ccd;">${b.num_qubits}</td>
                </tr>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                    <td style="padding:3px 8px 3px 0;color:#667;">Calibration</td>
                    <td style="color:#ccd;font-size:10px;">${calSummary}</td>
                </tr>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                    <td style="padding:3px 8px 3px 0;color:#667;">Threat Level</td>
                    <td style="color:${{ critical: '#ff3333', high: '#ff7722', medium: '#ffbb00', low: '#33cc66', none: '#556', info: '#4488cc' }[b.threatLevel || 'none'] || '#888'};">${(b.threatLevel || 'none').toUpperCase()}</td>
                </tr>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                    <td style="padding:3px 8px 3px 0;color:#667;">Active Threats</td>
                    <td style="color:${threatCount > 0 ? '#ff7722' : '#556'};">${threatCount}</td>
                </tr>
                <tr>
                    <td style="padding:3px 8px 3px 0;color:#667;">API Surface Score</td>
                    <td style="color:#ccd;">${b.api_surface_score !== undefined ? (b.api_surface_score * 100).toFixed(0) + '%' : 'N/A'}</td>
                </tr>
            </table>
            ${threatCount > 0 ? `
                <div style="font-size:10px;color:#667;letter-spacing:1px;margin-bottom:6px;">ACTIVE THREATS</div>
                <div style="display:flex;flex-direction:column;gap:3px;">${threatList}</div>
                ${threatCount > 5 ? `<div style="color:#556;font-size:9px;margin-top:4px;">+ ${threatCount - 5} more</div>` : ''}
            ` : ''}
        `;

        overlay.style.display = 'block';
    });

    // Close overlay on Escape (also handled by keyboard shortcuts)
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            overlay.style.display = 'none';
        }
    });

    // Close overlay when clicking on the canvas background (not on a backend)
    document.addEventListener('click', (e) => {
        if (e.target.id === 'qvis-canvas') {
            // Let StateMapper handle the backend click logic; overlay closes
            // via its own logic when no backend is hit (small delay)
            setTimeout(() => {
                // Only auto-close if the click didn't result in a selection
                const hitPanel = document.getElementById('threat-panel');
                if (hitPanel && !hitPanel.classList.contains('open')) {
                    overlay.style.display = 'none';
                }
            }, 50);
        }
    });
}

// ─── Critical Error Screen ───────────────────────────────────────────

function showCriticalError(fallbackManager, customMessage) {
    hideLoading();

    const container = document.getElementById('critical-error') || document.createElement('div');
    container.id = 'critical-error';

    let diagnostics = '';
    if (fallbackManager) {
        const report = fallbackManager.getDiagnosticReport();
        diagnostics = `
            <div class="error-diagnostics">
                <h3>DIAGNOSTICS</h3>
                <pre>${JSON.stringify(report, null, 2)}</pre>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="critical-error-content">
            <div class="error-icon">&#x26A0;</div>
            <h2>QVIS INITIALIZATION FAILED</h2>
            <p>${customMessage || 'Your browser does not support the required features to run QVis.'}</p>
            <p>Please use a modern browser with WebGL support (Chrome 90+, Firefox 88+, Edge 90+).</p>
            ${diagnostics}
            <button class="action-btn" onclick="location.reload()">RETRY</button>
        </div>
    `;

    document.body.appendChild(container);
}

// ─── Start ───────────────────────────────────────────────────────────

bootstrap();
