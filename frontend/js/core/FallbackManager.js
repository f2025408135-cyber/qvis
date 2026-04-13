/**
 * FallbackManager — Central orchestrator for all fallback and graceful degradation logic.
 * 
 * Responsibilities:
 *  - WebGL feature detection with fallback to Canvas 2D mode
 *  - CDN script load failure detection
 *  - Browser capability gating
 *  - Global error boundary (uncaught errors, rejected promises)
 *  - Provides a unified status API for the rest of the app
 */

const FALLBACK_STATE = {
    UNKNOWN: 'unknown',
    NOMINAL: 'nominal',
    DEGRADED: 'degraded',
    FALLBACK_2D: 'fallback_2d',
    CRITICAL: 'critical'
};

class FallbackManager {
    constructor() {
        this.state = FALLBACK_STATE.UNKNOWN;
        this.capabilities = {};
        this.scriptLoadErrors = [];
        this.listeners = new Map();
        this._lastKnownSnapshot = null;
    }

    /** Run all capability checks. Call once at startup. */
    detectCapabilities() {
        // WebGL support
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl2') || canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            this.capabilities.webgl = !!gl;
            this.capabilities.webglVersion = gl ? (canvas.getContext('webgl2') ? 2 : 1) : 0;
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                this.capabilities.gpuRenderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';
            }
        } catch (e) {
            this.capabilities.webgl = false;
            this.capabilities.webglVersion = 0;
        }

        // Canvas 2D support (our fallback)
        try {
            const canvas = document.createElement('canvas');
            this.capabilities.canvas2d = !!canvas.getContext('2d');
        } catch (e) {
            this.capabilities.canvas2d = false;
        }

        // WebSocket support
        this.capabilities.websocket = typeof WebSocket !== 'undefined';

        // Performance API
        this.capabilities.performance = typeof performance !== 'undefined' && typeof performance.now === 'function';

        // Typed Arrays (needed for particle system)
        this.capabilities.typedArrays = typeof Float32Array !== 'undefined';

        // ES6 Modules
        this.capabilities.modules = typeof Symbol !== 'undefined' && typeof Symbol() === 'symbol';

        // SharedArrayBuffer (not critical but nice)
        this.capabilities.sharedArrayBuffer = typeof SharedArrayBuffer !== 'undefined';

        // RequestAnimationFrame
        this.capabilities.raf = typeof requestAnimationFrame === 'function';

        // Clipboard API
        this.capabilities.clipboard = !!navigator.clipboard;

        // Touch support
        this.capabilities.touch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

        // Determine overall state
        if (this.capabilities.webgl && this.capabilities.typedArrays && this.capabilities.raf) {
            this.state = FALLBACK_STATE.NOMINAL;
        } else if (this.capabilities.canvas2d && this.capabilities.typedArrays && this.capabilities.raf) {
            this.state = FALLBACK_STATE.FALLBACK_2D;
        } else {
            this.state = FALLBACK_STATE.CRITICAL;
        }

        this._emit('stateChange', { state: this.state, capabilities: this.capabilities });
        console.log('[FallbackManager] Capabilities detected:', JSON.stringify(this.capabilities, null, 2));
        console.log('[FallbackManager] State:', this.state);

        return this.state;
    }

    /** Check if specific globals (Three.js, TWEEN) loaded correctly. */
    validateCriticalScripts() {
        this.scriptLoadErrors = [];

        if (typeof THREE === 'undefined') {
            this.scriptLoadErrors.push('THREE.js failed to load — WebGL rendering unavailable');
        } else {
            // Validate Three.js subsystems
            try {
                if (!THREE.Scene || !THREE.PerspectiveCamera || !THREE.WebGLRenderer) {
                    this.scriptLoadErrors.push('THREE.js loaded but core classes are missing');
                }
            } catch (e) {
                this.scriptLoadErrors.push('THREE.js loaded but is corrupted: ' + e.message);
            }
        }

        // Post-processing is optional (we can render without bloom)
        if (typeof THREE !== 'undefined' && !THREE.EffectComposer) {
            console.warn('[FallbackManager] Post-processing (bloom) unavailable — falling back to standard rendering');
        }

        // TWEEN is optional (camera animations degrade to instant)
        if (typeof TWEEN === 'undefined') {
            console.warn('[FallbackManager] TWEEN.js unavailable — camera animations disabled');
        }

        if (this.scriptLoadErrors.length > 0) {
            if (!this.capabilities.canvas2d) {
                this.state = FALLBACK_STATE.CRITICAL;
            } else {
                this.state = FALLBACK_STATE.FALLBACK_2D;
            }
            this._emit('stateChange', { state: this.state, errors: this.scriptLoadErrors });
        }

        return this.scriptLoadErrors;
    }

    /** Store last known good snapshot for offline/fallback rendering. */
    cacheSnapshot(snapshot) {
        this._lastKnownSnapshot = snapshot;
    }

    getLastKnownSnapshot() {
        return this._lastKnownSnapshot;
    }

    /** Register global error handlers. */
    installGlobalHandlers() {
        // Uncaught errors
        window.addEventListener('error', (event) => {
            console.error('[FallbackManager] Uncaught error:', event.error);
            this._emit('uncaughtError', {
                message: event.message,
                source: event.filename,
                line: event.lineno,
                col: event.colno,
                error: event.error
            });
        });

        // Unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            console.error('[FallbackManager] Unhandled rejection:', event.reason);
            this._emit('unhandledRejection', {
                reason: event.reason,
                promise: event.promise
            });
        });

        // WebSocket errors (global)
        window.addEventListener('offline', () => {
            console.warn('[FallbackManager] Browser went offline');
            this._emit('networkChange', { online: false });
        });

        window.addEventListener('online', () => {
            console.info('[FallbackManager] Browser came back online');
            this._emit('networkChange', { online: true });
        });
    }

    /** Event emitter pattern */
    on(event, callback) {
        if (!this.listeners.has(event)) this.listeners.set(event, new Set());
        this.listeners.get(event).add(callback);
        return () => this.listeners.get(event)?.delete(callback);
    }

    _emit(event, data) {
        if (this.listeners.has(event)) {
            this.listeners.get(event).forEach(cb => {
                try { cb(data); } catch (e) { console.error('[FallbackManager] Listener error:', e); }
            });
        }
    }

    /** Generate a diagnostic report (useful for DEF CON live debugging). */
    getDiagnosticReport() {
        return {
            state: this.state,
            userAgent: navigator.userAgent,
            capabilities: this.capabilities,
            scriptLoadErrors: this.scriptLoadErrors,
            hasCachedSnapshot: !!this._lastKnownSnapshot,
            connectionType: navigator.connection ? navigator.connection.effectiveType : 'unknown',
            deviceMemory: navigator.deviceMemory || 'unknown',
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            screenResolution: `${screen.width}x${screen.height}`,
            pixelRatio: window.devicePixelRatio
        };
    }
}

// Singleton
export const fallbackManager = new FallbackManager();
export { FALLBACK_STATE };
export default FallbackManager;
