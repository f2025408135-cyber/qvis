const CACHE_NAME = 'qvis-cache-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/css/main.css',
  '/js/main.js',
  '/js/state.js',
  '/js/simulation/ParticleSystem.js',
  '/js/simulation/Backend.js',
  '/js/simulation/Entanglement.js',
  '/js/simulation/ThreatVisuals.js',
  '/js/ui/Controls.js',
  '/js/ui/HUD.js',
  '/js/ui/ThreatPanel.js',
  '/js/ui/Legend.js',
  '/js/ui/Timeline.js',
  '/js/data/WSClient.js',
  '/js/data/StateMapper.js',
  '/js/core/FallbackManager.js',
  '/js/core/ToastManager.js',
  '/js/core/PerformanceMonitor.js',
  '/js/core/AudioEngine.js',
  '/js/renderers/Canvas2DFallback.js',
  // Dependencies from unpkg/cdnjs/jsdelivr (best effort caching)
  'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/EffectComposer.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/RenderPass.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/ShaderPass.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/shaders/CopyShader.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/shaders/LuminosityHighPassShader.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/UnrealBloomPass.js',
  'https://cdnjs.cloudflare.com/ajax/libs/tween.js/18.6.4/tween.umd.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        return cache.addAll(ASSETS_TO_CACHE.map(url => {
            // Avoid opaque responses by using Request objects or no-cors
            return new Request(url, { mode: url.startsWith('http') ? 'no-cors' : 'same-origin' });
        }));
      })
      .catch(err => {
         console.warn("Failed to cache some assets during install:", err);
      })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // We only cache GET requests
  if (event.request.method !== 'GET') return;
  // Ignore API calls and WebSockets from cache, we want offline viewing of the UI, but real-time data needs to fail gracefully to offline mode.
  if (event.request.url.includes('/api/') || event.request.url.includes('/ws/')) return;

  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Return cached response if found
        if (response) {
          return response;
        }

        // Clone the request because it's a one-time use stream
        const fetchRequest = event.request.clone();

        return fetch(fetchRequest).then(
          (response) => {
            // Check if we received a valid response
            if (!response || response.status !== 200 || response.type === 'error') {
              return response;
            }

            // Clone the response because it's a one-time use stream
            const responseToCache = response.clone();

            caches.open(CACHE_NAME)
              .then((cache) => {
                // Do not cache API or web socket streams
                if (!event.request.url.includes('/api/')) {
                  cache.put(event.request, responseToCache);
                }
              });

            return response;
          }
        ).catch(() => {
           // If fetch fails (offline), return cached index.html for navigation requests
           if (event.request.mode === 'navigate' || 
               (event.request.method === 'GET' && event.request.headers.get('accept').includes('text/html'))) {
             return caches.match('/index.html');
           }
        });
      })
  );
});
