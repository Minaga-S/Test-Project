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

    it('should parse open services from grepable output', async () => {
        const result = await nmapScanService.runScan({ target: '10.0.0.10', ports: '22,443' });

        expect(result.services.length).toBe(2);
    });

    it('should throw when scan target is missing', async () => {
        await expect(nmapScanService.runScan({})).rejects.toThrow('Nmap scan target is required');

        expect.assertions(1);
    });
});