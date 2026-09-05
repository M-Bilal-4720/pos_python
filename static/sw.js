const CACHE_NAME = 'isb-pos-v2';
const CACHE_URLS = [
  '/pos',
  '/static/favicon.jpg',
  '/static/isb_qr_emblem.png',
  '/static/theme.css'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(CACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => 
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  // Always network-first for HTML pages, APIs, and QR routes
  if (e.request.mode === 'navigate' || e.request.url.includes('/api/') || e.request.url.includes('/admin/qr/') || e.request.url.includes('/table/')) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  // Stale-while-revalidate for static assets
  e.respondWith(
    caches.match(e.request).then(cached => {
      const networked = fetch(e.request).then(res => {
        if (res.ok && res.status === 200) {
          const cacheCopy = res.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(e.request, cacheCopy));
        }
        return res;
      }).catch(() => cached);
      return cached || networked;
    })
  );
});
