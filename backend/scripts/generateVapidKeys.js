/**
 * Generate VAPID keys for browser push notifications.
 */

const webPush = require('web-push');

function run() {
    const keys = webPush.generateVAPIDKeys();

    console.log('Generated VAPID keys. Add these to backend/.env:');
    console.log('');
    console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
    console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
    console.log('VAPID_SUBJECT=mailto:you@example.com');
    console.log('');
    console.log('After saving .env, restart the backend server.');
}

run();