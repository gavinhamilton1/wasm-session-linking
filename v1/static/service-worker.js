self.addEventListener('push', function(event) {
    const options = {
        body: event.data.text(),
        icon: '/static/icon.png',
        badge: '/static/badge.png',
        vibrate: [100, 50, 100],
        data: {
            dateOfArrival: Date.now()
        }
    };

    event.waitUntil(
        self.registration.showNotification('Stronghold Step-up', options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('/mobile')
    );
}); 