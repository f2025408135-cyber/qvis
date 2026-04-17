/**
 * QVis — Audio Engine
 * Subtle procedural audio feedback using the Web Audio API.
 * All sounds are generated via oscillators — no external audio files needed.
 * Respects user preference via localStorage key 'qvis-audio-enabled'.
 * Auto-initializes on first user interaction (browser autoplay policy).
 */

export class AudioEngine {
    constructor() {
        this.ctx = null;
        this.initialized = false;
        this.enabled = null; // null = not yet checked
        this.masterGain = null;
        this.humOsc = null;
        this.humGain = null;
    }

    /**
     * Check user preference and create AudioContext on first interaction.
     * Must be called from a user-initiated event (click, keydown, etc.)
     * to satisfy browser autoplay policies.
     */
    init() {
        if (this.initialized) return;

        // Check localStorage preference
        const stored = localStorage.getItem('qvis-audio-enabled');
        if (stored === 'false') {
            this.enabled = false;
            return;
        }
        this.enabled = true;

        try {
            this.ctx = new (window.AudioContext || window.webkitAudioContext)();
            this.masterGain = this.ctx.createGain();
            this.masterGain.gain.value = 0.15;
            this.masterGain.connect(this.ctx.destination);

            this._startAmbientHum();
            this.initialized = true;
            console.log('[QVis] AudioEngine initialized');
        } catch (e) {
            console.warn('[QVis] AudioEngine init failed:', e);
            this.enabled = false;
        }
    }

    /**
     * Enable or disable audio. Persists to localStorage.
     */
    setEnabled(enabled) {
        this.enabled = enabled;
        localStorage.setItem('qvis-audio-enabled', String(enabled));

        if (enabled && !this.initialized) {
            this.init();
            return;
        }

        if (this.masterGain) {
            this.masterGain.gain.value = enabled ? 0.15 : 0;
        }
    }

    /**
     * Toggle audio on/off. Returns the new state.
     */
    toggle() {
        if (this.enabled === null) {
            this.init();
        }
        this.setEnabled(!this.enabled);
        return this.enabled;
    }

    /**
     * Play an alert tone — used when a critical threat is detected.
     * Sharp two-tone descending alert.
     */
    playAlert() {
        if (!this._canPlay()) return;

        const now = this.ctx.currentTime;

        // First tone (high)
        const osc1 = this.ctx.createOscillator();
        const gain1 = this.ctx.createGain();
        osc1.type = 'sine';
        osc1.frequency.setValueAtTime(880, now);
        osc1.frequency.exponentialRampToValueAtTime(440, now + 0.15);
        gain1.gain.setValueAtTime(0.3, now);
        gain1.gain.exponentialRampToValueAtTime(0.01, now + 0.2);
        osc1.connect(gain1);
        gain1.connect(this.masterGain);
        osc1.start(now);
        osc1.stop(now + 0.2);

        // Second tone (lower, after brief gap)
        const osc2 = this.ctx.createOscillator();
        const gain2 = this.ctx.createGain();
        osc2.type = 'sine';
        osc2.frequency.setValueAtTime(660, now + 0.22);
        osc2.frequency.exponentialRampToValueAtTime(330, now + 0.37);
        gain2.gain.setValueAtTime(0.25, now + 0.22);
        gain2.gain.exponentialRampToValueAtTime(0.01, now + 0.4);
        osc2.connect(gain2);
        gain2.connect(this.masterGain);
        osc2.start(now + 0.22);
        osc2.stop(now + 0.4);
    }

    /**
     * Play a connection tone — used when entanglement or link is established.
     * Soft ascending chime.
     */
    playConnect() {
        if (!this._canPlay()) return;

        const now = this.ctx.currentTime;

        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(220, now);
        osc.frequency.exponentialRampToValueAtTime(880, now + 0.15);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
        osc.connect(gain);
        gain.connect(this.masterGain);
        osc.start(now);
        osc.stop(now + 0.3);
    }

    /**
     * Play a click sound — used for UI interactions (button clicks, selections).
     * Short percussive tick.
     */
    playClick() {
        if (!this._canPlay()) return;

        const now = this.ctx.currentTime;

        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'square';
        osc.frequency.setValueAtTime(1200, now);
        osc.frequency.exponentialRampToValueAtTime(600, now + 0.03);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.05);
        osc.connect(gain);
        gain.connect(this.masterGain);
        osc.start(now);
        osc.stop(now + 0.05);
    }

    /**
     * Start a subtle low-frequency ambient hum.
     * Creates a warm drone that conveys "system active."
     */
    _startAmbientHum() {
        if (!this.ctx || !this.masterGain) return;

        this.humGain = this.ctx.createGain();
        this.humGain.gain.value = 0.04;

        // Low drone oscillator
        this.humOsc = this.ctx.createOscillator();
        this.humOsc.type = 'sine';
        this.humOsc.frequency.value = 55; // Low A
        this.humOsc.connect(this.humGain);
        this.humGain.connect(this.masterGain);
        this.humOsc.start();

        // Slight modulation for warmth
        const modOsc = this.ctx.createOscillator();
        const modGain = this.ctx.createGain();
        modOsc.type = 'sine';
        modOsc.frequency.value = 0.3; // Very slow LFO
        modGain.gain.value = 5; // Subtle pitch wobble
        modOsc.connect(modGain);
        modGain.connect(this.humOsc.frequency);
        modOsc.start();
    }

    /**
     * Internal guard: check if audio is available and enabled.
     */
    _canPlay() {
        if (!this.enabled || !this.ctx || !this.masterGain) return false;
        if (this.ctx.state === 'suspended') {
            this.ctx.resume();
        }
        return true;
    }

    /**
     * Cleanup: stop all oscillators and close the AudioContext.
     */
    destroy() {
        if (this.humOsc) {
            try { this.humOsc.stop(); } catch (e) { /* ignore */ }
        }
        if (this.ctx) {
            try { this.ctx.close(); } catch (e) { /* ignore */ }
        }
        this.initialized = false;
        this.ctx = null;
    }
}
