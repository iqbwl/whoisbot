const net = require('net');
const { IANA_WHOIS } = require('../config');
const { whoisServers } = require('../config/dataLoader');
const { detectRIR } = require('../utils/validator');

const MAX_SOCKET_BUFFER_BYTES = 256 * 1024; // 256 KB max socket output limit

const whoisQuery = (server, query, timeout = 12000) => {
    return new Promise((resolve, reject) => {
        if (!server || typeof server !== 'string') {
            return reject(new Error('Invalid WHOIS server'));
        }
        console.log(`WHOIS query "${query}" -> ${server}:43`);
        const socket = net.createConnection({ host: server.trim(), port: 43 });
        let data = '';
        let settled = false;

        const cleanup = () => {
            if (!socket.destroyed) socket.destroy();
        };

        const fail = (err) => {
            if (settled) return;
            settled = true;
            cleanup();
            reject(err);
        };

        socket.setTimeout(timeout);
        socket.on('connect', () => socket.write(query + '\r\n'));
        socket.on('data', (chunk) => {
            data += chunk.toString('utf8');
            if (Buffer.byteLength(data, 'utf8') > MAX_SOCKET_BUFFER_BYTES) {
                cleanup();
                if (!settled) {
                    settled = true;
                    resolve(data);
                }
            }
        });
        socket.on('timeout', () => fail(new Error(`WHOIS timeout: ${server}`)));
        socket.on('error', (err) => fail(err));
        socket.on('end', () => {
            if (settled) return;
            settled = true;
            cleanup();
            resolve(data);
        });
        socket.on('close', () => {
            if (settled) return;
            settled = true;
            cleanup();
            if (data) resolve(data); else reject(new Error(`WHOIS connection closed: ${server}`));
        });
    });
};

const WHOIS_NOT_FOUND_RE = /(no match for|not found|no entries found|no data found|object does not exist|nothing found|no matching record|status:\s*available|status:\s*free|domain not found|the queried object does not exist|malformed query|invalid query|invalid input)/i;
const WHOIS_DENIED_RE = /(not permitted|access denied|permission denied|quota exceeded|rate[ -]?limit(?:ed)? (?:exceeded|reached)|(?:exceeded|reached) (?:the )?rate[ -]?limit|query limit exceeded|maximum .* queries|exceeded the .*limit|too many requests|blocked for abuse|connection refused by policy)/i;

const whoisSaysNotFound = (text) => {
    if (!text || !text.trim()) return true;

    const head = text.split('\n')
        .filter(l => !/^\s*[%#]/.test(l))
        .slice(0, 30)
        .join('\n');

    const hasRecordSignature = /^[ \t]*(?:Domain Name|domain|Domain|Registry Domain ID)[ \t]*:[ \t]*\S/im.test(head);

    if (WHOIS_NOT_FOUND_RE.test(head)) return true;
    if (!hasRecordSignature && WHOIS_DENIED_RE.test(head)) return true;
    if (!/^[ \t]*[A-Za-z0-9][\w.\/ -]*:[ \t]*\S/m.test(text)) return true;

    return false;
};

const tldWhoisCache = new Map();

const getTldWhoisServer = async (domain) => {
    const parts = domain.split('.');

    for (let i = 1; i < parts.length; i++) {
        const suffix = parts.slice(i).join('.');
        if (whoisServers[suffix]) {
            console.log(`WHOIS server for ${domain}: ${whoisServers[suffix]} (static list, .${suffix})`);
            return whoisServers[suffix];
        }
    }

    const tld = parts[parts.length - 1];
    if (tldWhoisCache.has(tld)) return tldWhoisCache.get(tld);
    let server = null;
    try {
        const resp = await whoisQuery(IANA_WHOIS, tld, 6000);
        const m = resp.match(/^whois:\s*(\S+)\s*$/im);
        if (m) server = m[1].toLowerCase();
    } catch (e) {
        console.error(`IANA whois discovery failed for .${tld}:`, e.message);
    }
    tldWhoisCache.set(tld, server);
    return server;
};

const extractRegistrarWhoisServer = (text) => {
    const m = text.match(/Registrar WHOIS Server:\s*(\S+)/i);
    if (!m) return null;
    let server = m[1].trim().toLowerCase()
        .replace(/^r?whois:\/\//, '')
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/:\d+$/, '');
    if (!server || server === 'null' || !server.includes('.')) return null;
    return server;
};

const domainWhois = async (domain) => {
    if (!domain.includes('.')) return null;

    const registryServer = await getTldWhoisServer(domain);
    if (!registryServer) {
        console.log(`No WHOIS server known for ${domain} — will fall back to RDAP`);
        return null;
    }

    let registryResp;
    try {
        const q = /whois\.verisign-grs\.com|whois\.crsnic\.net/.test(registryServer)
            ? `domain ${domain}` : domain;
        registryResp = await whoisQuery(registryServer, q);
    } catch (e) {
        console.error(`WHOIS registry query failed (${registryServer}):`, e.message);
        return null;
    }

    if (whoisSaysNotFound(registryResp)) {
        console.log(`WHOIS says not found for ${domain} on ${registryServer}`);
        return null;
    }

    const registrarServer = extractRegistrarWhoisServer(registryResp);
    if (registrarServer && registrarServer !== registryServer && registryServer !== 'whois.registry.co' && registryServer !== 'whois.co.nl') {
        try {
            const registrarResp = await whoisQuery(registrarServer, domain, 3500);
            if (registrarResp && !whoisSaysNotFound(registrarResp)) {
                return { text: registrarResp, server: `${registryServer} → ${registrarServer}` };
            }
        } catch (e) {
            console.error(`WHOIS registrar referral failed (${registrarServer}):`, e.message);
        }
    }

    return { text: registryResp, server: registryServer };
};

const extractIpReferral = (text) => {
    const m = text.match(/(?:ReferralServer|refer):\s*(?:r?whois:\/\/)?(\S+)/i);
    if (!m) return null;
    return m[1].trim().toLowerCase().replace(/:\d+$/, '');
};

const ipWhois = async (ip) => {
    let server = detectRIR(ip).whoisServer;
    const visited = new Set();

    for (let hop = 0; hop < 3; hop++) {
        if (visited.has(server)) break;
        visited.add(server);

        let resp;
        try {
            const q = server === 'whois.arin.net' ? `n + ${ip}` : ip;
            resp = await whoisQuery(server, q);
        } catch (e) {
            console.error(`WHOIS IP query failed (${server}):`, e.message);
            return null;
        }

        const referral = extractIpReferral(resp);
        if (referral && referral !== server && !visited.has(referral)) {
            server = referral;
            continue;
        }

        if (whoisSaysNotFound(resp)) return null;
        return { text: resp, server };
    }
    return null;
};

module.exports = {
    whoisQuery,
    whoisSaysNotFound,
    getTldWhoisServer,
    extractRegistrarWhoisServer,
    domainWhois,
    extractIpReferral,
    ipWhois
};
