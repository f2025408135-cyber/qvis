import { ParticleSystem } from './simulation/ParticleSystem.js';
import { Backend } from './simulation/Backend.js';
import { Controls } from './ui/Controls.js';
import { WSClient } from './data/WSClient.js';
import { StateMapper } from './data/StateMapper.js';
import { EntanglementRenderer } from './simulation/Entanglement.js';
import { ThreatVisualManager } from './simulation/ThreatVisuals.js';
import { HUD } from './ui/HUD.js';
import { ThreatPanel } from './ui/ThreatPanel.js';
import { Legend } from './ui/Legend.js';

let scene, camera, renderer, composer, starSystem;
let lastTime = 0;
let controls;
let backends = new Map();
let particleSystem;
let threatVisualManager;
let entanglementRenderer;

let stateMapper;
let hud, threatPanel, legend;

function init() {
    const canvas = document.getElementById('qvis-canvas');
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x020408);
    // Add subtle fog to simulate density of deep space
    scene.fog = new THREE.FogExp2(0x020408, 0.0015);

    camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 3000);
    camera.position.set(0, 0, 600);
    // Store camera globally for raycasting
    window.__camera = camera;

    renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: false });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ReinhardToneMapping;
    renderer.toneMappingExposure = 1.5;

    // --- Post-Processing / Bloom ---
    const renderScene = new THREE.RenderPass(scene, camera);
    
    // Resolution, strength, radius, threshold
    const bloomPass = new THREE.UnrealBloomPass(
        new THREE.Vector2(window.innerWidth, window.innerHeight),
        1.5, 0.4, 0.1
    );

    composer = new THREE.EffectComposer(renderer);
    composer.addPass(renderScene);
    composer.addPass(bloomPass);

    // Lights
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

    // Cinematic Grid
    const gridHelper = new THREE.GridHelper(2000, 50, 0x112244, 0x050a14);
    gridHelper.position.y = -250;
    scene.add(gridHelper);

    particleSystem = new ParticleSystem(scene);
    threatVisualManager = new ThreatVisualManager(scene);
    entanglementRenderer = new EntanglementRenderer(scene);
    
    controls = new Controls(camera, canvas);
    window.__controls = controls; // allow global access for camera animation overrides
    
    hud = new HUD(document.getElementById('hud'));
    threatPanel = new ThreatPanel(document.getElementById('threat-panel'));
    legend = new Legend(document.getElementById('legend'));
    
    stateMapper = new StateMapper();

    const wsUrl = 'ws://127.0.0.1:8000/ws/simulation';
    const wsClient = new WSClient(wsUrl, (snapshot) => {
        document.getElementById('loading').style.display = 'none';
        stateMapper.mapSnapshot(
            snapshot, 
            backends, 
            scene,
            particleSystem, 
            threatVisualManager, 
            entanglementRenderer, 
            hud
        );
    });
    wsClient.connect();

    window.addEventListener('resize', onWindowResize);

    requestAnimationFrame(animate);
}

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

    // Custom shader for twinkling stars
    const material = new THREE.ShaderMaterial({
        uniforms: {
            time: { value: 0 }
        },
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
                // Soft glow edge
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
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
    composer.setSize(window.innerWidth, window.innerHeight);
}

function animate(time) {
    requestAnimationFrame(animate);
    
    // Optional chaining to prevent undefined TWEEN if script failed to load
    if (window.TWEEN) window.TWEEN.update(time);
    
    time *= 0.001;
    const deltaTime = time - lastTime;
    lastTime = time;

    if (starSystem) {
        starSystem.rotation.y += 0.00003;
        starSystem.material.uniforms.time.value = time * 2.0;
    }

    if (controls && !window.__isAnimatingCamera) controls.update();
    
    backends.forEach(backend => backend.update(deltaTime, time));
    if (particleSystem) particleSystem.update(deltaTime);
    if (threatVisualManager) threatVisualManager.update(deltaTime);
    if (entanglementRenderer) entanglementRenderer.update(deltaTime);

    composer.render();
}

init();
