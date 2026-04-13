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
import { FallbackManager, FALLBACK_STATE } from './core/FallbackManager.js';
import { toastManager } from './core/ToastManager.js';
import { perfMonitor } from './core/PerformanceMonitor.js';
import { Canvas2DFallback } from './renderers/Canvas2DFallback.js';

let scene, camera, renderer, composer, starSystem;
let lastTime = 0;
let controls;
let backends = new Map();
let particleSystem;
let threatVisualManager;
let entanglementRenderer;
let stateMapper;
let hud, threatPanel, legend;
let canvas2d = null;
let useWebGL = true;

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

        // Initialize performance monitor
        perfMonitor.init();

        // Stage 4: Connect WebSocket
        updateLoadingStage(LOADING_STAGES.CONNECTING);
        initWebSocket(fallbackManager);

        // Setup keyboard shortcuts
        initKeyboardShortcuts();

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
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host || '127.0.0.1:8000'}/ws/simulation`;
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

            case '?':
                // Show keyboard shortcuts help
                toastManager.info('ESC: Close panel | R: Reset | Space: Pause rotate | +/-: Zoom | Ctrl+F: FPS | H: Toggle HUD', 8000);
                break;
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
