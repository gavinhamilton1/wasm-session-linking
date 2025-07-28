const CACHE_NAME = 'jpm-digital-v1';
const urlsToCache = [
  '/mobile',
  '/static/css/styles.css',
  '/static/mobile.js',
  '/static/components/login-form.js',
  '/static/JPMorganLogo.png',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
}); 