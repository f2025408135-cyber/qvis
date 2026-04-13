/**
 * Controls — Camera orbit controls for the 3D visualization.
 *
 * Enhanced with:
 *  - Mouse, touch, and keyboard input
 *  - Idle auto-rotation (pauseable with Space)
 *  - Zoom limits and smooth damping
 *  - Focus trap prevention on UI elements
 *  - Reduced motion respect
 */

export class Controls {
    constructor(camera, domElement) {
        this.camera = camera;
        this.domElement = domElement;

        this.target = new THREE.Vector3();
        this._target = new THREE.Vector3();

        this.radius = 600;
        this.theta = Math.PI / 4;
        this.phi = Math.PI / 2.5;

        this.isDragging = false;
        this.previousMousePosition = { x: 0, y: 0 };
        this.lastInteractionTime = performance.now();

        // Idle rotation config
        this.idleRotationPaused = false;
        this.idleTimeout = 10000;      // 10s before auto-rotate kicks in
        this.idleRotationSpeed = 0.0003;

        // Reduced motion preference
        this.prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (this.prefersReducedMotion) {
            this.idleRotationSpeed = 0; // Disable auto-rotate
        }

        // Damping
        this.dampingFactor = 0.05;
        this.zoomSpeed = 0.5;
        this.rotateSpeed = 0.005;
        this.minRadius = 100;
        this.maxRadius = 2000;
        this.minPhi = 0.1;
        this.maxPhi = Math.PI - 0.1;

        // Bind events
        this._onMouseDown = this.onMouseDown.bind(this);
        this._onMouseMove = this.onMouseMove.bind(this);
        this._onMouseUp = this.onMouseUp.bind(this);
        this._onMouseWheel = this.onMouseWheel.bind(this);
        this._onTouchStart = this.onTouchStart.bind(this);
        this._onTouchMove = this.onTouchMove.bind(this);
        this._onTouchEnd = this.onTouchEnd.bind(this);
        this._onContextMenu = this.onContextMenu.bind(this);

        this.domElement.addEventListener('mousedown', this._onMouseDown);
        this.domElement.addEventListener('mousemove', this._onMouseMove);
        window.addEventListener('mouseup', this._onMouseUp);
        this.domElement.addEventListener('wheel', this._onMouseWheel, { passive: false });
        this.domElement.addEventListener('touchstart', this._onTouchStart, { passive: false });
        this.domElement.addEventListener('touchmove', this._onTouchMove, { passive: false });
        window.addEventListener('touchend', this._onTouchEnd);
        this.domElement.addEventListener('contextmenu', this._onContextMenu);
    }

    markInteraction() {
        this.lastInteractionTime = performance.now();
    }

    onMouseDown(event) {
        // Ignore if clicking on UI elements
        if (event.target !== this.domElement) return;

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

        this.theta -= deltaMove.x * this.rotateSpeed;
        this.phi -= deltaMove.y * this.rotateSpeed;
        this.phi = Math.max(this.minPhi, Math.min(this.maxPhi, this.phi));

        this.previousMousePosition = { x: event.clientX, y: event.clientY };
        this.markInteraction();
    }

    onMouseUp() {
        this.isDragging = false;
    }

    onMouseWheel(event) {
        event.preventDefault();
        this.radius += event.deltaY * this.zoomSpeed;
        this.radius = Math.max(this.minRadius, Math.min(this.maxRadius, this.radius));
        this.markInteraction();
    }

    onTouchStart(event) {
        if (event.touches.length === 1) {
            this.isDragging = true;
            this.previousMousePosition = { x: event.touches[0].clientX, y: event.touches[0].clientY };
            this.markInteraction();
        } else if (event.touches.length === 2) {
            // Pinch zoom
            this._pinchStartDistance = this._getPinchDistance(event.touches);
            this._pinchStartRadius = this.radius;
        }
    }

    onTouchMove(event) {
        if (event.touches.length === 1 && this.isDragging) {
            event.preventDefault();
            const deltaMove = {
                x: event.touches[0].clientX - this.previousMousePosition.x,
                y: event.touches[0].clientY - this.previousMousePosition.y
            };
            this.theta -= deltaMove.x * this.rotateSpeed;
            this.phi -= deltaMove.y * this.rotateSpeed;
            this.phi = Math.max(this.minPhi, Math.min(this.maxPhi, this.phi));
            this.previousMousePosition = { x: event.touches[0].clientX, y: event.touches[0].clientY };
            this.markInteraction();
        } else if (event.touches.length === 2 && this._pinchStartDistance) {
            event.preventDefault();
            const dist = this._getPinchDistance(event.touches);
            const scale = this._pinchStartDistance / dist;
            this.radius = Math.max(this.minRadius, Math.min(this.maxRadius, this._pinchStartRadius * scale));
            this.markInteraction();
        }
    }

    onTouchEnd() {
        this.isDragging = false;
        this._pinchStartDistance = null;
    }

    onContextMenu(event) {
        // Prevent right-click menu on the canvas (keeps it clean for demos)
        event.preventDefault();
    }

    _getPinchDistance(touches) {
        const dx = touches[0].clientX - touches[1].clientX;
        const dy = touches[0].clientY - touches[1].clientY;
        return Math.sqrt(dx * dx + dy * dy);
    }

    update() {
        const timeSinceInteraction = performance.now() - this.lastInteractionTime;

        // Auto-rotate when idle and not paused
        if (!this.isDragging && !this.idleRotationPaused && this.idleRotationSpeed > 0) {
            if (timeSinceInteraction > this.idleTimeout) {
                this.theta += this.idleRotationSpeed;
            }
        }

        const targetX = this.target.x + this.radius * Math.sin(this.phi) * Math.cos(this.theta);
        const targetY = this.target.y + this.radius * Math.cos(this.phi);
        const targetZ = this.target.z + this.radius * Math.sin(this.phi) * Math.sin(this.theta);

        this._target.set(targetX, targetY, targetZ);
        this.camera.position.lerp(this._target, this.dampingFactor);
        this.camera.lookAt(this.target);
    }

    /** Cleanup event listeners. */
    dispose() {
        this.domElement.removeEventListener('mousedown', this._onMouseDown);
        this.domElement.removeEventListener('mousemove', this._onMouseMove);
        window.removeEventListener('mouseup', this._onMouseUp);
        this.domElement.removeEventListener('wheel', this._onMouseWheel);
        this.domElement.removeEventListener('touchstart', this._onTouchStart);
        this.domElement.removeEventListener('touchmove', this._onTouchMove);
        window.removeEventListener('touchend', this._onTouchEnd);
        this.domElement.removeEventListener('contextmenu', this._onContextMenu);
    }
}
