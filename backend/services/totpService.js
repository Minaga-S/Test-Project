// NOTE: Service layer: contains core business logic used by controllers.

const { authenticator } = require('otplib');
const qrcode = require('qrcode');

const DEFAULT_TOTP_WINDOW = 1;

authenticator.options = {
    window: DEFAULT_TOTP_WINDOW,
};

function normalizeTotpCode(code) {
    if (typeof code !== 'string' && typeof code !== 'number') {
        return '';
    }

    return String(code).replace(/\s+/g, '');
}

function generateSecret() {
    return authenticator.generateSecret();
}

function buildOtpAuthUrl({ appName, email, secret }) {
    return authenticator.keyuri(email, appName, secret);
}

function verifyToken(secret, token) {
    const normalizedToken = normalizeTotpCode(token);
    if (!secret || !normalizedToken) {
        return false;
    }

    return authenticator.check(normalizedToken, secret);
}

async function generateQrCodeDataUrl(otpAuthUrl) {
    return qrcode.toDataURL(otpAuthUrl);
}

module.exports = {
    generateSecret,
    buildOtpAuthUrl,
    verifyToken,
    generateQrCodeDataUrl,
};
