/**
 * Nmap Scan Service
 */
// NOTE: Provides target-scope validation helpers for local/private scanning.
const ALLOWED_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);
const PRIVATE_IPV4_RANGES = [
    [10, 0, 0, 0, 8],
    [127, 0, 0, 0, 8],
    [169, 254, 0, 0, 16],
    [172, 16, 0, 0, 12],
    [192, 168, 0, 0, 16],
    [100, 64, 0, 0, 10],
];

function parseIpv4Address(value) {
    const octets = String(value || '').trim().split('.').map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
        return null;
    }

    return octets;
}

function normalizeRequesterIp(requestIp) {
    const rawIp = String(requestIp || '').split(',')[0].trim();
    if (!rawIp) {
        return '';
    }

    if (rawIp.startsWith('::ffff:')) {
        return rawIp.slice(7);
    }

    if (rawIp === '::1') {
        return '127.0.0.1';
    }

    return rawIp;
}

function isPrivateIpv4Address(value) {
    const octets = parseIpv4Address(value);
    if (!octets) {
        return false;
    }

    return PRIVATE_IPV4_RANGES.some(([first, second, third, fourth, prefixLength]) => {
        if (prefixLength === 8) {
            return octets[0] === first;
        }

        if (prefixLength === 10) {
            return octets[0] === first && octets[1] >= 64 && octets[1] <= 127;
        }

        if (prefixLength === 12) {
            return octets[0] === first && octets[1] >= 16 && octets[1] <= 31;
        }

        if (prefixLength === 16) {
            return octets[0] === first && octets[1] === second;
        }

        return octets[0] === first && octets[1] === second && octets[2] === third && octets[3] === fourth;
    });
}

function isLoopbackIpv4Address(value) {
    const octets = parseIpv4Address(value);
    if (!octets) {
        return false;
    }

    return octets[0] === 127;
}

function isLocalHostname(target) {
    const normalizedTarget = String(target || '').trim().toLowerCase();
    if (ALLOWED_HOSTNAMES.has(normalizedTarget)) {
        return true;
    }

    return normalizedTarget.endsWith('.local')
        || normalizedTarget.endsWith('.internal')
        || normalizedTarget.endsWith('.lan');
}

function isAllowedScanTarget(target) {
    const normalizedTarget = String(target || '').trim();
    if (!normalizedTarget) {
        return false;
    }

    if (ALLOWED_HOSTNAMES.has(normalizedTarget.toLowerCase()) || isLocalHostname(normalizedTarget)) {
        return true;
    }

    return isPrivateIpv4Address(normalizedTarget);
}

function areInSameIpv4Subnet(target, requestIp, subnetMaskBits = 24) {
    const targetOctets = parseIpv4Address(target);
    const requesterOctets = parseIpv4Address(requestIp);

    if (!targetOctets || !requesterOctets) {
        return false;
    }

    if (subnetMaskBits === 24) {
        return targetOctets[0] === requesterOctets[0]
            && targetOctets[1] === requesterOctets[1]
            && targetOctets[2] === requesterOctets[2];
    }

    return false;
}

function assertTargetWithinRequesterNetwork(target, requestIp) {
    const normalizedRequesterIp = normalizeRequesterIp(requestIp);
    if (!normalizedRequesterIp || !isPrivateIpv4Address(normalizedRequesterIp)) {
        return;
    }

    // Requests originating from localhost are trusted to scan any allowed private target
    // reachable by the local scanner host.
    if (isLoopbackIpv4Address(normalizedRequesterIp)) {
        return;
    }

    if (isLocalHostname(target)) {
        return;
    }

    if (areInSameIpv4Subnet(target, normalizedRequesterIp)) {
        return;
    }

    throw new Error('Scan target must be on the same private subnet as the requester');
}

module.exports = {
    isAllowedScanTarget,
    isPrivateIpv4Address,
    isLoopbackIpv4Address,
    isLocalHostname,
    normalizeRequesterIp,
    areInSameIpv4Subnet,
    assertTargetWithinRequesterNetwork,
};



