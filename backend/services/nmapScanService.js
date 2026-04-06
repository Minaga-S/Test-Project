/**
 * Nmap Scan Service
 */
// NOTE: Runs Nmap and normalizes grepable output into structured scan results.

const { execFile } = require('child_process');
const util = require('util');

const execFileAsync = util.promisify(execFile);
const DEFAULT_NMAP_TIMEOUT_MS = Number(process.env.NMAP_SCAN_TIMEOUT_MS) || 60000;

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

function parsePortsLine(output) {
    const portsLineMatch = output.match(/Ports:\s+([^\n]+)/);
    if (!portsLineMatch) {
        return [];
    }

    return portsLineMatch[1]
        .split(', ')
        .map((entry) => {
            const [portText, state, protocol, , serviceName] = entry.split('/');
            const port = Number(portText);
            return {
                port: Number.isInteger(port) ? port : null,
                state: state || '',
                protocol: protocol || '',
                service: serviceName || 'unknown',
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

function buildCommandArgs(target, portsInput) {
    const args = ['-Pn', '-sV', '-O', '--open'];
    const normalizedPorts = normalizePorts(portsInput);

    if (normalizedPorts) {
        args.push('-p', normalizedPorts);
    }

    args.push('-oG', '-', target);
    return args;
}

async function runScan({ target, ports } = {}) {
    const normalizedTarget = String(target || '').trim();
    if (!normalizedTarget) {
        throw new Error('Nmap scan target is required');
    }

    const args = buildCommandArgs(normalizedTarget, ports);

    try {
        const { stdout = '' } = await execFileAsync('nmap', args, {
            maxBuffer: 5 * 1024 * 1024,
            timeout: DEFAULT_NMAP_TIMEOUT_MS,
        });

        const openServices = parsePortsLine(stdout);
        const hostState = parseHostState(stdout);

        return {
            command: 'nmap',
            args,
            target: normalizedTarget,
            requestedPorts: normalizePorts(ports),
            openPorts: openServices.map((entry) => entry.port),
            services: openServices,
            hostState,
            rawOutput: stdout,
        };
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error('Nmap is not installed or not available on PATH');
        }

        throw new Error(`Nmap scan failed for ${normalizedTarget}: ${error.message}`);
    }
}

module.exports = {
    runScan,
    buildCommandArgs,
    normalizePorts,
    parsePortsLine,
    parseHostState,
};