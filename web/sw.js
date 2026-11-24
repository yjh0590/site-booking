self.addEventListener("push", (e) => {
  const d = e.data ? e.data.json() : {};
  e.waitUntil(self.registration.showNotification(d.title || "🐣 콕콕!", {
    body: d.body || "",
    icon: "/icon.png",
    badge: "/icon.png",
    vibrate: [120, 60, 120],
    data: { url: d.url || "/" },
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data.url));
});
