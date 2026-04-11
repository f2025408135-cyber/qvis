export class Controls {
    constructor(camera, domElement) {
        this.camera = camera;
        this.domElement = domElement;
        
        this.target = new THREE.Vector3();
        
        this.radius = 500;
        this.theta = 0;
        this.phi = Math.PI / 2;
        
        this.isDragging = false;
        this.previousMousePosition = { x: 0, y: 0 };
        
        this.lastInteractionTime = performance.now();
        
        this.domElement.addEventListener('mousedown', this.onMouseDown.bind(this));
        this.domElement.addEventListener('mousemove', this.onMouseMove.bind(this));
        window.addEventListener('mouseup', this.onMouseUp.bind(this));
        this.domElement.addEventListener('wheel', this.onMouseWheel.bind(this), {passive: false});
        
        this.domElement.addEventListener('touchstart', this.onTouchStart.bind(this), {passive: false});
        this.domElement.addEventListener('touchmove', this.onTouchMove.bind(this), {passive: false});
        window.addEventListener('touchend', this.onTouchEnd.bind(this));
    }
    
    markInteraction() {
        this.lastInteractionTime = performance.now();
    }
    
    onMouseDown(event) {
        this.isDragging = true;
        this.previousMousePosition = { x: event.clientX, y: event.clientY };
        this.markInteraction();
    }
    
    onMouseMove(event) {
        if (!this.isDragging) return;
        
        const deltaMove = {
            x: event.clientX - this.previousMousePosition.x,
            y: event.clientY - this.previousMousePosition.y
        };
        
        this.theta -= deltaMove.x * 0.005;
        this.phi -= deltaMove.y * 0.005;
        
        this.phi = Math.max(0.1, Math.min(Math.PI - 0.1, this.phi));
        
        this.previousMousePosition = { x: event.clientX, y: event.clientY };
        this.markInteraction();
    }
    
    onMouseUp() {
        this.isDragging = false;
    }
    
    onMouseWheel(event) {
        event.preventDefault();
        this.radius += event.deltaY * 0.5;
        this.radius = Math.max(100, Math.min(1000, this.radius));
        this.markInteraction();
    }
    
    onTouchStart(event) {
        if (event.touches.length === 1) {
            this.isDragging = true;
            this.previousMousePosition = { x: event.touches[0].clientX, y: event.touches[0].clientY };
            this.markInteraction();
        }
    }
    
    onTouchMove(event) {
        if (!this.isDragging || event.touches.length !== 1) return;
        event.preventDefault();
        const deltaMove = {
            x: event.touches[0].clientX - this.previousMousePosition.x,
            y: event.touches[0].clientY - this.previousMousePosition.y
        };
        this.theta -= deltaMove.x * 0.005;
        this.phi -= deltaMove.y * 0.005;
        this.phi = Math.max(0.1, Math.min(Math.PI - 0.1, this.phi));
        this.previousMousePosition = { x: event.touches[0].clientX, y: event.touches[0].clientY };
        this.markInteraction();
    }
    
    onTouchEnd() {
        this.isDragging = false;
    }
    
    update() {
        const timeSinceInteraction = performance.now() - this.lastInteractionTime;
        
        if (timeSinceInteraction > 10000 && !this.isDragging) {
            this.theta += 0.0003;
        }
        
        const targetX = this.radius * Math.sin(this.phi) * Math.cos(this.theta);
        const targetY = this.radius * Math.cos(this.phi);
        const targetZ = this.radius * Math.sin(this.phi) * Math.sin(this.theta);
        
        this.camera.position.lerp(new THREE.Vector3(targetX, targetY, targetZ), 0.05);
        this.camera.lookAt(this.target);
    }
}
