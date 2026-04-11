export class WSClient {
    constructor(url, onSnapshot) {
        this.url = url;
        this.onSnapshot = onSnapshot;
        this.reconnectDelay = 1000;
        this.maxReconnectDelay = 30000;
        this.ws = null;
        this.reconnectTimer = null;
    }

    connect() {
        if (this.ws) {
            this.ws.close();
        }

        console.log(`Connecting to ${this.url}...`);
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectDelay = 1000;
            
            const statusEl = document.getElementById('connection-status');
            if(statusEl) {
                statusEl.className = 'status-pill live';
                statusEl.textContent = 'LIVE';
            }
        };

        this.ws.onmessage = (event) => {
            try {
                const snapshot = JSON.parse(event.data);
                this.onSnapshot(snapshot);
            } catch (e) {
                console.error("Error parsing snapshot JSON:", e);
            }
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.scheduleReconnect();
            
            const statusEl = document.getElementById('connection-status');
            if(statusEl) {
                statusEl.className = 'status-pill disconnected';
                statusEl.textContent = 'DISCONNECTED';
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    scheduleReconnect() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
        }
        console.log(`Reconnecting in ${this.reconnectDelay}ms...`);
        this.reconnectTimer = setTimeout(() => {
            this.connect();
        }, this.reconnectDelay);
        
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    }

    disconnect() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
        }
        if (this.ws) {
            this.ws.close();
        }
    }
}
