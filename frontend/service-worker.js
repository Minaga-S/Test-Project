self.addEventListener('push', (event) => {
    const payload = event.data ? event.data.json() : {};
    const title = payload.title || 'HCGS Alert';
    const options = {
        body: payload.body || 'You have a new security notification.',
        icon: payload.icon || '/assets/pwa-icon.svg',
        badge: payload.badge || '/assets/pwa-icon.svg',
        data: {
            url: payload.url || '/dashboard.html',
        },
        tag: payload.tag || 'hcgs-notification',
    };

    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();

    const targetUrl = event.notification.data?.url || '/dashboard.html';

    event.waitUntil((async () => {
        const clientsList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        for (const client of clientsList) {
            if ('focus' in client) {
                return client.focus();
            }
        }

        if (self.clients.openWindow) {
            return self.clients.openWindow(targetUrl);
        }

        return null;
    })());
});