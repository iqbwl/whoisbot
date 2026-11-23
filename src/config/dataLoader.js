const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '../../');

function loadRdapRegistryMap() {
    const registryMap = new Map();
    try {
        const filePath = path.join(rootDir, 'rdap-registry.json');
        if (fs.existsSync(filePath)) {
            const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            if (Array.isArray(raw)) {
                for (const item of raw) {
                    if (item && item.tld) {
                        registryMap.set(item.tld.toLowerCase(), item);
                    }
                }
            }
        }
    } catch (err) {
        console.error('Error loading rdap-registry.json:', err.message);
    }
    return registryMap;
}

function loadWhoisServers() {
    try {
        const filePath = path.join(rootDir, 'whois-servers.json');
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
    } catch (err) {
        console.error('Error loading whois-servers.json:', err.message);
    }
    return {};
}

const rdapRegistryMap = loadRdapRegistryMap();
const whoisServers = loadWhoisServers();

module.exports = {
    rdapRegistryMap,
    whoisServers
};
