/**
 * Nmap Scan Service
 */
// NOTE: Runs Nmap only against localhost/private-network targets and normalizes grepable output.

const { execFile } = require('child_process');
const util = require('util');

const execFileAsync = util.promisify(execFile);
const DEFAULT_NMAP_TIMEOUT_MS = Number(process.env.NMAP_SCAN_TIMEOUT_MS) || 60000;
const ALLOWED_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);
const PRIVATE_IPV4_RANGES = [
    [10, 0, 0, 0, 8],
    [127, 0, 0, 0, 8],
    [169, 254, 0, 0, 16],
    [172, 16, 0, 0, 12],
    [192, 168, 0, 0, 16],
    [100, 64, 0, 0, 10],
];

function normalizePorts(portsInput) {
    if (Array.isArray(portsInput)) {
        return portsInput
            .map((port) => Number(port))
            .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
            .join(',');
    }

    const rawPorts = String(portsInput || '').trim();
    if (!rawPorts) {
        return '';
    }

    return rawPorts
        .split(',')
        .map((port) => Number(port.trim()))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
        .join(',');
}

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

function assertAllowedTarget(target) {
    if (!isAllowedScanTarget(target)) {
        throw new Error('Nmap scans are restricted to localhost and private-network targets');
    }
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

    if (isLocalHostname(target)) {
        return;
    }

    if (areInSameIpv4Subnet(target, normalizedRequesterIp)) {
        return;
    }

    throw new Error('Scan target must be on the same private subnet as the requester');
}

function parsePortsLine(output) {
    const portsLineMatch = output.match(/Ports:\s+([^\n]+)/);
    if (!portsLineMatch) {
        return [];
    }

    return portsLineMatch[1]
        .split(', ')
        .map((entry) => {
            const parts = entry.split('/');
            const port = Number(parts[0]);
            const version = parts.slice(5).join('/').replace(/^\/+|\/+$/g, '').trim();

            return {
                port: Number.isInteger(port) ? port : null,
                state: parts[1] || '',
                protocol: parts[2] || '',
                service: parts[4] || 'unknown',
                version,
            };
        })
        .filter((entry) => entry.port !== null && entry.state === 'open');
}

function parseHostState(output) {
    const hostLineMatch = output.match(/Host:\s+([^\s]+)\s+\((.*?)\)\s+Status:\s+([^\n]+)/);
    if (!hostLineMatch) {
        return {
            hostAddress: '',
            hostName: '',
            state: 'unknown',
        };
    }

    return {
        hostAddress: hostLineMatch[1] || '',
        hostName: hostLineMatch[2] || '',
        state: hostLineMatch[3] || 'unknown',
    };
}

function parseOsInfo(output) {
    const normalizedOutput = String(output || '');
    if (!normalizedOutput) {
        return '';
    }

    const osDetailsMatch = normalizedOutput.match(/OS details:\s*([^\n]+)/i);
    if (osDetailsMatch?.[1]) {
        return osDetailsMatch[1].trim();
    }

    const osGuessMatch = normalizedOutput.match(/Aggressive OS guesses:\s*([^\n]+)/i);
    if (osGuessMatch?.[1]) {
        return osGuessMatch[1]
            .split(',')
            .map((entry) => entry.trim())
            .filter(Boolean)[0] || '';
    }

    const runningMatch = normalizedOutput.match(/Running:\s*([^\n]+)/i);
    if (runningMatch?.[1]) {
        return runningMatch[1].trim();
    }

    if (/Too many fingerprints match/i.test(normalizedOutput)) {
        return 'Unable to determine (inconclusive fingerprints)';
    }

    return '';
}


function parseOsCpe(output) {
    const normalizedOutput = String(output || '');
    if (!normalizedOutput) {
        return '';
    }

    const cpeMatch = normalizedOutput.match(/OS CPE:\s*([^\n]+)/i);
    return cpeMatch?.[1] ? cpeMatch[1].trim() : '';
}
function buildCommandArgs(target, portsInput) {
    const args = ['-Pn', '-sV', '--version-light', '--open'];
    const normalizedPorts = normalizePorts(portsInput);

    if (normalizedPorts) {
        args.push('-p', normalizedPorts);
    }

    args.push('-oG', '-', target);
    return args;
}

function buildOsDetectionArgs(target) {
    return ['-Pn', '-O', '--osscan-guess', '--max-os-tries', '1', target];
}

function buildUnavailableErrorMessage(normalizedTarget, error) {
    const deploymentHint = process.env.RENDER ? ' Deploy with the backend Dockerfile so Nmap is installed in the image.' : ' Install Nmap locally and ensure it is on PATH.';
    return new Error(`Nmap scan failed for ${normalizedTarget}: ${error.message}.${deploymentHint}`);
}

async function runScan({ target, ports, requestIp } = {}) {
    const normalizedTarget = String(target || '').trim();
    if (!normalizedTarget) {
        throw new Error('Nmap scan target is required');
    }

    assertAllowedTarget(normalizedTarget);
    assertTargetWithinRequesterNetwork(normalizedTarget, requestIp);

    const args = buildCommandArgs(normalizedTarget, ports);

    try {
        const { stdout = '' } = await execFileAsync('nmap', args, {
            maxBuffer: 5 * 1024 * 1024,
            timeout: DEFAULT_NMAP_TIMEOUT_MS,
        });

        const openServices = parsePortsLine(stdout);
        const hostState = parseHostState(stdout);
        let osInfo = parseOsInfo(stdout);
        let osCpe = parseOsCpe(stdout);

        if (!osInfo || !osCpe) {
            try {
                const osArgs = buildOsDetectionArgs(normalizedTarget);
                const { stdout: osStdout = '' } = await execFileAsync('nmap', osArgs, {
                    maxBuffer: 5 * 1024 * 1024,
                    timeout: DEFAULT_NMAP_TIMEOUT_MS,
                });
                osInfo = osInfo || parseOsInfo(osStdout);
                osCpe = osCpe || parseOsCpe(osStdout);
            } catch (osError) {
                osInfo = osInfo || '';
                osCpe = osCpe || '';
            }
        }

        return {
            command: 'nmap',
            args,
            target: normalizedTarget,
            requestedPorts: normalizePorts(ports),
            openPorts: openServices.map((entry) => entry.port),
            services: openServices,
            hostState,
            osInfo,
            osCpe,
            rawOutput: stdout,
        };
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw buildUnavailableErrorMessage(normalizedTarget, error);
        }

        throw new Error(`Nmap scan failed for ${normalizedTarget}: ${error.message}`);
    }
}

module.exports = {
    runScan,
    buildCommandArgs,
    buildOsDetectionArgs,
    normalizePorts,
    parsePortsLine,
    parseHostState,
    parseOsInfo,
    parseOsCpe,
    isAllowedScanTarget,
    isPrivateIpv4Address,
    isLocalHostname,
    normalizeRequesterIp,
    areInSameIpv4Subnet,
    assertTargetWithinRequesterNetwork,
};



