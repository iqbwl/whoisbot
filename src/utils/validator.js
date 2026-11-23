const net = require('net');
const { RIRS } = require('../config');
const { rdapRegistryMap, whoisServers } = require('../config/dataLoader');

const isIP = (input) => {
    if (!input || typeof input !== 'string') return false;
    const clean = input.trim();
    const ver = net.isIP(clean);
    return ver === 0 ? false : ver;
};

const normalizeInput = (input) => {
    if (!input || typeof input !== 'string') return '';
    return input.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/:\d+$/, '')
        .replace(/\.$/, '');
};

const detectRIR = (ip) => {
    if (!ip) return RIRS.ARIN;
    if (ip.includes(':')) {
        const clean = ip.toLowerCase();
        if (clean.startsWith('2a0') || clean.startsWith('2a1')) return RIRS.RIPE;
        if (clean.startsWith('240') || clean.startsWith('2001:e') || clean.startsWith('2001:d')) return RIRS.APNIC;
        if (clean.startsWith('280')) return RIRS.LACNIC;
        if (clean.startsWith('2c0')) return RIRS.AFRINIC;
        return RIRS.ARIN;
    }
    const firstOctet = parseInt(ip.split('.')[0], 10);
    if ([1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 102, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223].includes(firstOctet)) return RIRS.APNIC;
    if ([2, 5, 25, 31, 37, 46, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217].includes(firstOctet)) return RIRS.RIPE;
    if ([177, 179, 181, 186, 187, 189, 190, 191, 200, 201].includes(firstOctet)) return RIRS.LACNIC;
    if ([41, 102, 105, 154, 196, 197].includes(firstOctet)) return RIRS.AFRINIC;
    return RIRS.ARIN;
};

const extractTld = (domain) => {
    if (!domain || typeof domain !== 'string') return '';
    const parts = domain.split('.');
    if (parts.length < 2) return '';
    if (parts.length >= 3) {
        const multiLevelTld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
        if (rdapRegistryMap.has(multiLevelTld) || whoisServers[multiLevelTld]) {
            return multiLevelTld;
        }
    }
    return parts[parts.length - 1];
};

module.exports = {
    isIP,
    normalizeInput,
    detectRIR,
    extractTld
};
