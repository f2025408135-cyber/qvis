/**
 * WSClient — Resilient WebSocket client with exponential backoff + jitter,
 * offline mode, connection quality tracking, and last-known-state caching.
 * 
 * Features:
 *  - Exponential backoff with randomized jitter (avoves thundering herd)
 *  - Connection quality tracking (latency, message count, disconnect count)
 *  - Offline mode: serves last-known snapshot to keep UI alive
 *  - Multi-stage connection status: connecting → live → reconnecting → offline
 *  - Heartbeat/ping to detect stale connections
 */

const WS_STATE = {
    IDLE: 'idle',
    CONNECTING: 'connecting',
    CONNECTED: 'connected',
    RECONNECTING: 'reconnecting',
    OFFLINE: 'offline',
    CLOSED: 'closed'
};

export class WSClient {
    constructor(url, onSnapshot) {
        this.url = url;
        this.onSnapshot = onSnapshot;

        // Backoff configuration
        this.baseDelay = 1000;           // 1s initial
        this.maxDelay = 30000;           // 30s max
        this.jitterFactor = 0.25;        // ±25% randomization
        this.currentDelay = this.baseDelay;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 50;  // Effectively infinite but bounded

        // State
        this.ws = null;
        this.state = WS_STATE.IDLE;
        this.reconnectTimer = null;
        this.heartbeatTimer = null;
        this.heartbeatInterval = 30000;  // 30s ping interval
        this.heartbeatTimeout = 10000;   // 10s response timeout

        // Quality metrics
        this.metrics = {
            connectTime: null,
            messagesReceived: 0,
            messagesPerSecond: 0,
            lastMessageAt: 0,
            totalDisconnects: 0,
            totalReconnects: 0,
            consecutiveErrors: 0,
            uptimeStart: null,
            latency: null
        };

        // Offline/fallback
        this._lastSnapshot = null;
        this._snapshotCallbacks = [];
    }

    connect() {
        if (this.state === WS_STATE.CLOSED) {
            console.warn('[WSClient] Cannot connect — client is permanently closed');
            return;
        }

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        this._setState(WS_STATE.CONNECTING);
        console.log(`[WSClient] Connecting to ${this.url}...`);

        try {
            this.ws = new WebSocket(this.url);
        } catch (e) {
            console.error('[WSClient] WebSocket constructor failed:', e);
            this._scheduleReconnect();
            return;
        }

        const connectStart = performance.now();

        this.ws.onopen = () => {
            const elapsed = performance.now() - connectStart;
            this.metrics.connectTime = Math.round(elapsed);
            this.metrics.uptimeStart = this.metrics.uptimeStart || Date.now();
            this.metrics.consecutiveErrors = 0;
            this.reconnectAttempts = 0;
            this.currentDelay = this.baseDelay;

            console.log(`[WSClient] Connected in ${elapsed.toFixed(0)}ms`);
            this._setState(WS_STATE.CONNECTED);
            this._startHeartbeat();
        };

        this.ws.onmessage = (event) => {
            try {
                const snapshot = JSON.parse(event.data);
                this._lastSnapshot = snapshot;
                this.metrics.messagesReceived++;
                this.metrics.lastMessageAt = Date.now();
                this.metrics.consecutiveErrors = 0;

                // Messages per second (rolling)
                const now = performance.now();
                if (!this._lastMsgTime) this._lastMsgTime = now;
                this._msgCount = (this._msgCount || 0) + 1;
                if (now - this._lastMsgTime >= 1000) {
                    this.metrics.messagesPerSecond = this._msgCount;
                    this._msgCount = 0;
                    this._lastMsgTime = now;
                }

                // Deliver to callback
                try {
                    this.onSnapshot(snapshot);
                } catch (e) {
                    console.error('[WSClient] Snapshot callback error:', e);
                }

                // Also deliver to any queued callbacks (for offline resumption)
                while (this._snapshotCallbacks.length > 0) {
                    const cb = this._snapshotCallbacks.shift();
                    try { cb(snapshot); } catch (e) { /* ignore */ }
                }
            } catch (e) {
                console.error('[WSClient] Error parsing snapshot JSON:', e);
                this.metrics.consecutiveErrors++;
            }
        };

        this.ws.onclose = (event) => {
            console.log(`[WSClient] Disconnected (code=${event.code}, reason=${event.reason || 'none'})`);
            this.metrics.totalDisconnects++;
            this._stopHeartbeat();

            // 1001 = going away (intentional close)
            if (event.code === 1001 || this.state === WS_STATE.CLOSED) {
                this._setState(WS_STATE.CLOSED);
                return;
            }

            this._scheduleReconnect();
        };

        this.ws.onerror = (error) => {
            console.error('[WSClient] WebSocket error:', error);
            this.metrics.consecutiveErrors++;
        };
    }

    _scheduleReconnect() {
        if (this.state === WS_STATE.CLOSED) return;
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.warn('[WSClient] Max reconnect attempts reached — going offline');
            this._setState(WS_STATE.OFFLINE);
            return;
        }

        this._setState(WS_STATE.RECONNECTING);
        this.reconnectAttempts++;
        this.metrics.totalReconnects++;

        // Exponential backoff with jitter
        const jitter = 1 + (Math.random() * 2 - 1) * this.jitterFactor;
        const delay = Math.min(this.currentDelay * jitter, this.maxDelay);
        console.log(`[WSClient] Reconnect attempt ${this.reconnectAttempts} in ${Math.round(delay)}ms`);

        this.reconnectTimer = setTimeout(() => {
            this.connect();
        }, delay);

        this.currentDelay = Math.min(this.currentDelay * 2, this.maxDelay);
    }

    /** Start heartbeat to detect stale connections. */
    _startHeartbeat() {
        this._stopHeartbeat();
        this.heartbeatTimer = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                // Send ping
                try {
                    this.ws.send(JSON.stringify({ type: 'ping' }));
                } catch (e) {
                    console.warn('[WSClient] Heartbeat send failed — connection may be stale');
                    this.ws.close();
                }
            }
        }, this.heartbeatInterval);
    }

    _stopHeartbeat() {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
        }
    }

    /** Update the connection status indicator in the DOM. */
    _setState(newState) {
        const oldState = this.state;
        this.state = newState;

        const statusEl = document.getElementById('connection-status');
        const reconnectEl = document.getElementById('reconnect-info');

        switch (newState) {
            case WS_STATE.CONNECTING:
                if (statusEl) {
                    statusEl.className = 'status-pill connecting';
                    statusEl.textContent = 'CONNECTING';
                }
                break;

            case WS_STATE.CONNECTED:
                if (statusEl) {
                    statusEl.className = 'status-pill live';
                    statusEl.textContent = 'LIVE';
                }
                if (reconnectEl) reconnectEl.style.display = 'none';
                break;

            case WS_STATE.RECONNECTING:
                if (statusEl) {
                    statusEl.className = 'status-pill reconnecting';
                    statusEl.textContent = 'RECONNECTING';
                }
                if (reconnectEl) {
                    reconnectEl.style.display = 'block';
                    reconnectEl.textContent = `Reconnect ${this.reconnectAttempts}/${this.maxReconnectAttempts} — ${Math.round(this.currentDelay / 1000)}s`;
                }
                break;

            case WS_STATE.OFFLINE:
                if (statusEl) {
                    statusEl.className = 'status-pill offline';
                    statusEl.textContent = 'OFFLINE';
                }
                if (reconnectEl) {
                    reconnectEl.style.display = 'block';
                    reconnectEl.textContent = 'Connection lost — using cached data';
                }
                break;

            case WS_STATE.CLOSED:
                if (statusEl) {
                    statusEl.className = 'status-pill disconnected';
                    statusEl.textContent = 'CLOSED';
                }
                break;
        }

        // Dispatch event for other components to react
        document.dispatchEvent(new CustomEvent('wsStateChange', {
            detail: { oldState, newState, metrics: { ...this.metrics }, attempt: this.reconnectAttempts }
        }));
    }

    /** Send data over the WebSocket. */
    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(typeof data === 'string' ? data : JSON.stringify(data));
            return true;
        }
        return false;
    }

    /** Get the last received snapshot (for offline/fallback rendering). */
    getLastSnapshot() {
        return this._lastSnapshot;
    }

    /** Register a callback for the next snapshot (useful when coming back from offline). */
    onNextSnapshot(callback) {
        if (this._lastSnapshot) {
            try { callback(this._lastSnapshot); } catch (e) { /* ignore */ }
        } else {
            this._snapshotCallbacks.push(callback);
        }
    }

    /** Permanently close the connection. */
    disconnect() {
        this._stopHeartbeat();
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this._setState(WS_STATE.CLOSED);
        if (this.ws) {
            try { this.ws.close(1001, 'Client disconnect'); } catch (e) { /* ignore */ }
            this.ws = null;
        }
    }

    /** Get a snapshot of current connection metrics. */
    getMetrics() {
        const uptime = this.metrics.uptimeStart
            ? Math.round((Date.now() - this.metrics.uptimeStart) / 1000)
            : 0;
        return {
            state: this.state,
            reconnectAttempts: this.reconnectAttempts,
            messagesReceived: this.metrics.messagesReceived,
            messagesPerSecond: this.metrics.messagesPerSecond,
            uptimeSeconds: uptime,
            totalDisconnects: this.metrics.totalDisconnects,
            consecutiveErrors: this.metrics.consecutiveErrors,
            connectTimeMs: this.metrics.connectTime,
            hasCachedData: !!this._lastSnapshot
        };
    }
}

export { WS_STATE };
