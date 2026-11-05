// Lets phones install the site as an app. It deliberately caches nothing:
// people's data always comes fresh from the server, and nothing private stays on the device.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => { /* network as normal */ });
