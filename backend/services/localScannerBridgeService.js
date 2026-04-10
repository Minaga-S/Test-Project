/**
 * Local Scanner Bridge Service
 */
// NOTE: Issues short-lived, one-time scan tokens for the local scanner companion app.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nmapScanService = require('./nmapScanService');

const DEFAULT_TOKEN_TTL_SECONDS = Number(process.env.LOCAL_SCANNER_BRIDGE_TOKEN_TTL_SECONDS) || 180;
const BRIDGE_ISSUER = 'hcg.local-scanner';

const consumedTokenExpiries = new Map();

class LocalScannerBridgeError extends Error {
    constructor(code, message, statusCode = 400) {
        super(message);
        this.name = 'LocalScannerBridgeError';
        this.code = code;
        this.statusCode = statusCode;
    }
}

function getBridgeSecret() {
    const secret = String(process.env.LOCAL_SCANNER_BRIDGE_SECRET || process.env.JWT_SECRET || '').trim();
    if (!secret) {
        throw new LocalScannerBridgeError('BRIDGE_SECRET_MISSING', 'Local scanner bridge secret is not configured', 500);
    }

    return secret;
}

function normalizeText(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function sanitizeVulnerabilityProfile(profile = {}) {
    return {
        osName: normalizeText(profile.osName),
        vendor: normalizeText(profile.vendor),
        product: normalizeText(profile.product),
        productVersion: normalizeText(profile.productVersion),
        cpeUri: normalizeText(profile.cpeUri),
    };
}

function sanitizeScanRequest(scanRequest = {}) {
    const target = normalizeText(scanRequest.liveScan?.target);
    const ports = normalizeText(scanRequest.liveScan?.ports);

    return {
        assetId: normalizeText(scanRequest.assetId),
        assetName: normalizeText(scanRequest.assetName),
        assetType: normalizeText(scanRequest.assetType),
        liveScan: {
            enabled: true,
            target,
            ports,
            frequency: 'OnDemand',
        },
        vulnerabilityProfile: sanitizeVulnerabilityProfile(scanRequest.vulnerabilityProfile || {}),
    };
}

function pruneConsumedTokens() {
    const nowSeconds = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of consumedTokenExpiries.entries()) {
        if (exp <= nowSeconds) {
            consumedTokenExpiries.delete(jti);
        }
    }
}

function verifyTargetScope(target, requestIp) {
    if (!target) {
        throw new LocalScannerBridgeError('TARGET_REQUIRED', 'Scan target is required');
    }

    if (!nmapScanService.isAllowedScanTarget(target)) {
        throw new LocalScannerBridgeError('TARGET_NOT_ALLOWED', 'Live scan target must be localhost or a private-network address');
    }

    try {
        nmapScanService.assertTargetWithinRequesterNetwork(target, requestIp || '');
    } catch (error) {
        throw new LocalScannerBridgeError('TARGET_OUT_OF_SCOPE', error.message);
    }
}

function issueScanToken(scanRequest = {}, requestMeta = {}) {
    const sanitized = sanitizeScanRequest(scanRequest);
    verifyTargetScope(sanitized.liveScan.target, requestMeta.ipAddress || '');

    const userId = normalizeText(requestMeta.userId);
    if (!userId) {
        throw new LocalScannerBridgeError('USER_REQUIRED', 'Authenticated user is required', 401);
    }

    const jti = crypto.randomUUID();
    const issuedAtSeconds = Math.floor(Date.now() / 1000);
    const expiresAtSeconds = issuedAtSeconds + DEFAULT_TOKEN_TTL_SECONDS;
    const bridgeSecret = getBridgeSecret();

    const payload = {
        sub: userId,
        jti,
        type: 'local-scan',
        asset: {
            assetId: sanitized.assetId,
            assetName: sanitized.assetName,
            assetType: sanitized.assetType,
            liveScan: sanitized.liveScan,
            vulnerabilityProfile: sanitized.vulnerabilityProfile,
        },
    };

    const token = jwt.sign(payload, bridgeSecret, {
        algorithm: 'HS256',
        issuer: BRIDGE_ISSUER,
        expiresIn: DEFAULT_TOKEN_TTL_SECONDS,
    });

    return {
        bridgeToken: token,
        expiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
        scanRequest: sanitized,
    };
}

function consumeScanToken(token) {
    pruneConsumedTokens();

    const rawToken = normalizeText(token);
    if (!rawToken) {
        throw new LocalScannerBridgeError('TOKEN_REQUIRED', 'Bridge token is required', 401);
    }

    let decoded;
    try {
        decoded = jwt.verify(rawToken, getBridgeSecret(), {
            algorithms: ['HS256'],
            issuer: BRIDGE_ISSUER,
        });
    } catch (error) {
        throw new LocalScannerBridgeError('TOKEN_INVALID', 'Bridge token is invalid or expired', 401);
    }

    if (decoded?.type !== 'local-scan' || !decoded?.jti) {
        throw new LocalScannerBridgeError('TOKEN_INVALID', 'Bridge token payload is invalid', 401);
    }

    if (consumedTokenExpiries.has(decoded.jti)) {
        throw new LocalScannerBridgeError('TOKEN_ALREADY_USED', 'Bridge token has already been used', 409);
    }

    consumedTokenExpiries.set(decoded.jti, Number(decoded.exp) || Math.floor(Date.now() / 1000));

    return {
        userId: String(decoded.sub || ''),
        asset: {
            assetId: normalizeText(decoded.asset?.assetId),
            assetName: normalizeText(decoded.asset?.assetName),
            assetType: normalizeText(decoded.asset?.assetType),
            liveScan: {
                enabled: true,
                target: normalizeText(decoded.asset?.liveScan?.target),
                ports: normalizeText(decoded.asset?.liveScan?.ports),
                frequency: 'OnDemand',
            },
            vulnerabilityProfile: sanitizeVulnerabilityProfile(decoded.asset?.vulnerabilityProfile || {}),
        },
    };
}

module.exports = {
    LocalScannerBridgeError,
    issueScanToken,
    consumeScanToken,
};
