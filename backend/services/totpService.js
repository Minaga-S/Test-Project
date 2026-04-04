// NOTE: Service layer: contains core business logic used by controllers.

const { authenticator } = require('otplib');
const qrcode = require('qrcode');

const DEFAULT_TOTP_WINDOW = 2;
const DEFAULT_TOTP_STEP_SECONDS = 30;
const TOTP_TOKEN_LENGTH = 6;

function getTotpWindow() {
    const parsed = Number.parseInt(process.env.TOTP_WINDOW || '', 10);
    return Number.isNaN(parsed) ? DEFAULT_TOTP_WINDOW : parsed;
}

authenticator.options = {
    window: getTotpWindow(),
    step: DEFAULT_TOTP_STEP_SECONDS,
};

function normalizeTotpCode(code) {
    if (typeof code !== 'string' && typeof code !== 'number') {
        return '';
    }

    return String(code)
        .replace(/\D+/g, '')
        .slice(0, TOTP_TOKEN_LENGTH);
}

function generateSecret() {
    return authenticator.generateSecret();
}

function buildOtpAuthUrl({ appName, email, secret }) {
    return authenticator.keyuri(email, appName, secret);
}

function isNormalizedTotpCode(code) {
    return /^\d{6}$/.test(code);
}

function verifyToken(secret, token) {
    const normalizedToken = normalizeTotpCode(token);
    if (!secret || !isNormalizedTotpCode(normalizedToken)) {
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
