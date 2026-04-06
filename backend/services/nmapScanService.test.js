const childProcess = require('child_process');
const nmapScanService = require('./nmapScanService');

jest.mock('child_process', () => ({
    execFile: jest.fn((command, args, options, callback) => {
        callback(null, {
            stdout: 'Host: 10.0.0.10 () Status: Up\nPorts: 22/open/tcp//ssh///, 443/open/tcp//https///',
        });
    }),
}));

describe('nmapScanService', () => {
    beforeEach(() => {
        childProcess.execFile.mockClear();
    });

    it('should build Nmap arguments with requested ports', async () => {
        await nmapScanService.runScan({ target: '10.0.0.10', ports: '22,443' });

        expect(childProcess.execFile.mock.calls[0][1].includes('-p')).toBe(true);
    });

    it('should not include OS fingerprinting flags in the scan command', async () => {
        await nmapScanService.runScan({ target: '10.0.0.10', ports: '22,443' });

        expect(childProcess.execFile.mock.calls[0][1].includes('-O')).toBe(false);
    });

    it('should parse open services from grepable output', async () => {
        const result = await nmapScanService.runScan({ target: '10.0.0.10', ports: '22,443' });

        expect(result.services.length).toBe(2);
    });

    it('should reject public targets before invoking Nmap', async () => {
        await expect(nmapScanService.runScan({ target: '8.8.8.8', ports: '22' })).rejects.toThrow('Nmap scans are restricted to localhost and private-network targets');

        expect(childProcess.execFile).not.toHaveBeenCalled();
    });

    it('should reject target outside requester subnet for private requester IP', async () => {
        await expect(nmapScanService.runScan({
            target: '10.0.0.10',
            ports: '22',
            requestIp: '10.0.1.25',
        })).rejects.toThrow('Scan target must be on the same private subnet as the requester');
    });

    it('should allow target in same requester subnet', async () => {
        await nmapScanService.runScan({
            target: '10.0.0.10',
            ports: '22',
            requestIp: '10.0.0.8',
        });

        expect(childProcess.execFile).toHaveBeenCalledTimes(1);
    });

    it('should throw when scan target is missing', async () => {
        await expect(nmapScanService.runScan({})).rejects.toThrow('Nmap scan target is required');

        expect.assertions(1);
    });
});