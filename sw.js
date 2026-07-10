const CACHE = 'babypass-v2';
const ASSETS = ['./index.html', './style.css', './manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ).then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const url = e.request.url;
  if (url.includes('firestore') || url.includes('firebase') ||
      url.includes('googleapis') || url.includes('gstatic') ||
      url.includes('jsdelivr') || url.includes('fonts.google')) return;

  // Network-first for the HTML shell so new deploys are picked up right away.
  // Falls back to the cached copy only when offline.
  if (e.request.mode === 'navigate' || url.endsWith('/') || url.endsWith('.html')) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache-first for static assets (css, icons, manifest).
  e.respondWith(caches.match(e.request).then(cached => cached || fetch(e.request)));
});
