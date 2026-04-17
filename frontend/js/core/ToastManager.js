/**
 * ToastManager — Non-intrusive notification system.
 * 
 * Shows contextual status messages without disrupting the visualization.
 * Supports: info, warning, error, success types with auto-dismiss.
 * Stacks toasts with smooth enter/exit animations.
 */

const TOAST_TYPES = {
    info:    { icon: '\u2139', cssClass: 'toast-info',    duration: 4000 },
    warning: { icon: '\u26A0', cssClass: 'toast-warning', duration: 5000 },
    error:   { icon: '\u2716', cssClass: 'toast-error',   duration: 7000 },
    success: { icon: '\u2713', cssClass: 'toast-success', duration: 3000 }
};

class ToastManager {
    constructor() {
        this.container = null;
        this.activeToasts = [];
        this.maxVisible = 5;
        this._initialized = false;
    }

    /** Mount the toast container into the DOM. Call once. */
    init() {
        if (this._initialized) return;
        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        this.container.setAttribute('role', 'log');
        this.container.setAttribute('aria-live', 'polite');
        this.container.setAttribute('aria-atomic', 'false');
        document.body.appendChild(this.container);
        this._initialized = true;
    }

    /** Show a toast notification. */
    show(message, type = 'info', duration = null) {
        if (!this._initialized) this.init();

        const config = TOAST_TYPES[type] || TOAST_TYPES.info;
        const toastDuration = duration !== null ? duration : config.duration;

        const toast = document.createElement('div');
        toast.className = `toast ${config.cssClass}`;
        toast.setAttribute('role', 'status');
        toast.innerHTML = `
            <span class="toast-icon">${config.icon}</span>
            <span class="toast-message">${this._escapeHTML(message)}</span>
            <button class="toast-dismiss" aria-label="Dismiss notification">&times;</button>
        `;

        // Dismiss button
        const dismissBtn = toast.querySelector('.toast-dismiss');
        dismissBtn.addEventListener('click', () => this._dismiss(toast));

        // Stack management
        if (this.activeToasts.length >= this.maxVisible) {
            this._dismiss(this.activeToasts[0]);
        }

        this.container.appendChild(toast);
        this.activeToasts.push(toast);

        // Trigger enter animation
        requestAnimationFrame(() => {
            toast.classList.add('toast-visible');
        });

        // Auto-dismiss
        const timer = setTimeout(() => this._dismiss(toast), toastDuration);
        toast._dismissTimer = timer;

        return toast;
    }

    /** Dismiss a toast with exit animation. */
    _dismiss(toast) {
        if (!toast || !toast.parentNode) return;
        if (toast._dismissed) return;
        toast._dismissed = true;

        clearTimeout(toast._dismissTimer);

        toast.classList.remove('toast-visible');
        toast.classList.add('toast-exit');

        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
            const idx = this.activeToasts.indexOf(toast);
            if (idx > -1) this.activeToasts.splice(idx, 1);
        }, 400);
    }

    /** Dismiss all active toasts. */
    dismissAll() {
        [...this.activeToasts].forEach(t => this._dismiss(t));
    }

    /** Convenience methods */
    info(message, duration)    { return this.show(message, 'info', duration); }
    warning(message, duration) { return this.show(message, 'warning', duration); }
    error(message, duration)   { return this.show(message, 'error', duration); }
    success(message, duration) { return this.show(message, 'success', duration); }

    /** HTML-escape for safety. */
    _escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
}

// Singleton
export const toastManager = new ToastManager();
export default ToastManager;
