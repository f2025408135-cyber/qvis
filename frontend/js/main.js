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

let scene, camera, renderer, starSystem;
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
    scene.background = new THREE.Color(0x030810);

    camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 2000);
    camera.position.set(0, 0, 500);

    renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: false });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    const ambientLight = new THREE.AmbientLight(0x111133, 0.5);
    scene.add(ambientLight);

    const light1 = new THREE.PointLight(0x2244aa, 1.0);
    light1.position.set(200, 100, 100);
    scene.add(light1);

    const light2 = new THREE.PointLight(0x113355, 0.8);
    light2.position.set(-200, -100, 200);
    scene.add(light2);

    const light3 = new THREE.PointLight(0x001122, 0.4);
    light3.position.set(0, 200, -100);
    scene.add(light3);

    createStarField();

    const gridHelper = new THREE.GridHelper(1000, 30, 0x112244, 0x0a1a2a);
    gridHelper.position.y = -200;
    scene.add(gridHelper);

    particleSystem = new ParticleSystem(scene);
    threatVisualManager = new ThreatVisualManager(scene);
    entanglementRenderer = new EntanglementRenderer(scene);
    
    controls = new Controls(camera, canvas);
    
    hud = new HUD(document.getElementById('hud'));
    threatPanel = new ThreatPanel(document.getElementById('threat-panel'));
    legend = new Legend(document.getElementById('legend'));
    
    stateMapper = new StateMapper();

    const wsUrl = `ws://127.0.0.1:8000/ws/simulation`;
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

    for (let i = 0; i < 2000; i++) {
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        const radius = 1500;

        const x = radius * Math.sin(phi) * Math.cos(theta);
        const y = radius * Math.sin(phi) * Math.sin(theta);
        const z = radius * Math.cos(phi);

        vertices.push(x, y, z);
    }

    geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));

    const material = new THREE.PointsMaterial({ 
        color: 0xaaccff, 
        size: 0.8,
        transparent: true,
        opacity: 0.6
    });

    starSystem = new THREE.Points(geometry, material);
    scene.add(starSystem);
}

function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

function animate(time) {
    requestAnimationFrame(animate);
    time *= 0.001;
    const deltaTime = time - lastTime;
    lastTime = time;

    if (starSystem) {
        starSystem.rotation.y += 0.00005;
    }

    if (controls) controls.update();
    
    backends.forEach(backend => backend.update(deltaTime, time));
    if (particleSystem) particleSystem.update(deltaTime);
    if (threatVisualManager) threatVisualManager.update(deltaTime);
    if (entanglementRenderer) entanglementRenderer.update(deltaTime);

    renderer.render(scene, camera);
}

init();
