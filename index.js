require('dotenv').config();
const { Telegraf } = require('telegraf');
const axios = require('axios');
const net = require('net');

const BOT_TOKEN = process.env.BOT_TOKEN || 'YOUR_BOT_TOKEN_HERE';
const fs = require('fs');
const path = require('path');

// Load configurations
const loadRdapRegistry = () => {
    try {
        const configPath = path.join(__dirname, 'rdap-registry.json');
        if (fs.existsSync(configPath)) {
            return JSON.parse(fs.readFileSync(configPath, 'utf8'));
        }
    } catch (e) {
        console.error('Error loading rdap-registry.json:', e);
    }
    return [];
};

const rdapRegistry = loadRdapRegistry();

// Static TLD -> WHOIS server map (generated from the IANA root zone DB).
// Primary source for WHOIS server discovery — no runtime dependency on
// whois.iana.org (which is blocked/unreachable from some networks).
const loadWhoisServers = () => {
    try {
        const configPath = path.join(__dirname, 'whois-servers.json');
        if (fs.existsSync(configPath)) {
            return JSON.parse(fs.readFileSync(configPath, 'utf8'));
        }
    } catch (e) {
        console.error('Error loading whois-servers.json:', e);
    }
    return {};
};

const whoisServers = loadWhoisServers();

const RIRS = {
    ARIN: { name: 'ARIN', rdapServer: 'https://rdap.arin.net/registry', whoisServer: 'whois.arin.net' },
    RIPE: { name: 'RIPE NCC', rdapServer: 'https://rdap.db.ripe.net', whoisServer: 'whois.ripe.net' },
    APNIC: { name: 'APNIC', rdapServer: 'https://rdap.apnic.net', whoisServer: 'whois.apnic.net' },
    LACNIC: { name: 'LACNIC', rdapServer: 'https://rdap.lacnic.net/rdap', whoisServer: 'whois.lacnic.net' },
    AFRINIC: { name: 'AFRINIC', rdapServer: 'https://rdap.afrinic.net/rdap', whoisServer: 'whois.afrinic.net' }
};

const IANA_WHOIS = 'whois.iana.org';
const MAX_OUTPUT_CHARS = 3400; // keep under Telegram's 4096 message limit

const bot = new Telegraf(BOT_TOKEN);

// Helpers
const isIP = (d) => {
    // IPv4
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(d)) return 4;
    // IPv6 (Simplified)
    if (/^(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}$/i.test(d) || d.includes('::')) return 6;
    return false;
};

const normalizeInput = (d) => {
    d = d.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/\.$/, '');
    return d;
};

const detectRIR = (ip) => {
    if (ip.includes(':')) return RIRS.ARIN;
    const firstOctet = parseInt(ip.split('.')[0], 10);
    if ([1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 102, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223].includes(firstOctet)) return RIRS.APNIC;
    if ([2, 5, 25, 31, 37, 46, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217].includes(firstOctet)) return RIRS.RIPE;
    if ([177, 179, 181, 186, 187, 189, 190, 191, 200, 201].includes(firstOctet)) return RIRS.LACNIC;
    if ([41, 102, 105, 154, 196, 197].includes(firstOctet)) return RIRS.AFRINIC;
    return RIRS.ARIN;
};

const extractTld = (domain) => {
    const parts = domain.split('.');
    if (parts.length < 2) return '';
    if (parts.length >= 3) {
        const multiLevelTld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
        if (rdapRegistry.find(e => e.tld === multiLevelTld)) return multiLevelTld;
    }
    return parts[parts.length - 1];
};

const escapeMdV2 = (s) => {
    return String(s).replace(/([_*[\]()~`>#+\-=|{}.!\\\\])/g, '\\$1');
};

const httpGetJson = async (url, timeout = 10000) => {
    try {
        console.log(`Querying: ${url}`);
        const response = await axios.get(url, {
            timeout,
            headers: { 'Accept': 'application/rdap+json' },
            validateStatus: (status) => status >= 200 && status < 400 // Accept 301/302 redirects if axios doesn't follow automatically
        });
        return [response.data, response.status, null];
    } catch (error) {
        console.error(`Error querying ${url}:`, error.message);
        if (error.response) {
            return [null, error.response.status, `HTTP ${error.response.status}`];
        }
        return [null, 0, error.message];
    }
};

// ============================================================
// WHOIS (port 43) — primary lookup engine
// ============================================================

/**
 * Raw WHOIS query over TCP port 43.
 * Resolves with the full response text, or rejects on error/timeout.
 */
const whoisQuery = (server, query, timeout = 12000) => {
    return new Promise((resolve, reject) => {
        console.log(`WHOIS query "${query}" -> ${server}:43`);
        const socket = net.createConnection({ host: server, port: 43 });
        let data = '';
        let settled = false;

        const fail = (err) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            reject(err);
        };

        socket.setTimeout(timeout);
        socket.on('connect', () => socket.write(query + '\r\n'));
        socket.on('data', (chunk) => { data += chunk.toString('utf8'); });
        socket.on('timeout', () => fail(new Error(`WHOIS timeout: ${server}`)));
        socket.on('error', (err) => fail(err));
        socket.on('end', () => {
            if (settled) return;
            settled = true;
            resolve(data);
        });
        socket.on('close', () => {
            if (settled) return;
            settled = true;
            if (data) resolve(data); else reject(new Error(`WHOIS connection closed: ${server}`));
        });
    });
};

/** Patterns that indicate "object not found" in WHOIS responses. */
const WHOIS_NOT_FOUND_RE = /(no match for|not found|no entries found|no data found|object does not exist|nothing found|no matching record|status:\s*available|status:\s*free|domain not found|the queried object does not exist|malformed query|invalid query|invalid input)/i;

/** Patterns indicating the WHOIS server refused/limited the query (fallback to RDAP). */
const WHOIS_DENIED_RE = /(not permitted|access denied|permission denied|quota exceeded|rate limit|query limit|maximum .* queries|exceeded the .*limit|too many requests|blocked for abuse|connection refused by policy)/i;

const whoisSaysNotFound = (text) => {
    if (!text || !text.trim()) return true;
    if (WHOIS_DENIED_RE.test(text)) return true;
    // A real record should contain at least one "Key: value" line
    if (!/^[ \t]*[\w.\/-]+[ \t]*:[ \t]*\S/m.test(text)) return true;
    // Only inspect the first ~30 non-comment lines (avoid false hits in legal footers)
    const head = text.split('\n')
        .filter(l => !/^\s*[%#]/.test(l))
        .slice(0, 30)
        .join('\n');
    return WHOIS_NOT_FOUND_RE.test(head);
};

// Cache TLD -> whois server discovered from IANA (per process lifetime)
const tldWhoisCache = new Map();

/**
 * Find the WHOIS server for a domain.
 * 1. Static whois-servers.json (from IANA root DB) — checks the longest
 *    matching suffix first (e.g. "web.id" before "id").
 * 2. Live discovery via whois.iana.org (only if not in the static list).
 */
const getTldWhoisServer = async (domain) => {
    const parts = domain.split('.');

    // 1. Static list: longest suffix match (web.id -> id -> …)
    for (let i = 1; i < parts.length; i++) {
        const suffix = parts.slice(i).join('.');
        if (whoisServers[suffix]) {
            console.log(`WHOIS server for ${domain}: ${whoisServers[suffix]} (static list, .${suffix})`);
            return whoisServers[suffix];
        }
    }

    // 2. Live IANA discovery (best effort — may be blocked on some networks)
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

/** Extract "Registrar WHOIS Server:" referral from a registry response. */
const extractRegistrarWhoisServer = (text) => {
    const m = text.match(/Registrar WHOIS Server:\s*(\S+)/i);
    if (!m) return null;
    let server = m[1].trim().toLowerCase()
        .replace(/^r?whois:\/\//, '')
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '');
    if (!server || server === 'null' || !server.includes('.')) return null;
    return server;
};

/**
 * WHOIS lookup for a domain.
 * Returns { text, server } on success, or null when the whois server is
 * unknown / unreachable / reports "not found" (caller falls back to RDAP).
 */
const domainWhois = async (domain) => {
    if (!domain.includes('.')) return null;

    const registryServer = await getTldWhoisServer(domain);
    if (!registryServer) {
        console.log(`No WHOIS server known for ${domain} — will fall back to RDAP`);
        return null;
    }

    let registryResp;
    try {
        // Verisign (.com/.net) needs "domain <name>" to avoid nameserver matches
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

    // Follow registrar referral (thin registries like .com/.net) for richer data
    const registrarServer = extractRegistrarWhoisServer(registryResp);
    if (registrarServer && registrarServer !== registryServer) {
        try {
            const registrarResp = await whoisQuery(registrarServer, domain);
            if (registrarResp && !whoisSaysNotFound(registrarResp)) {
                return { text: registrarResp, server: `${registryServer} → ${registrarServer}` };
            }
        } catch (e) {
            console.error(`WHOIS registrar referral failed (${registrarServer}):`, e.message);
        }
    }

    return { text: registryResp, server: registryServer };
};

/** Extract a referral RIR server from an ARIN/IANA style response. */
const extractIpReferral = (text) => {
    const m = text.match(/(?:ReferralServer|refer):\s*(?:r?whois:\/\/)?(\S+)/i);
    if (!m) return null;
    return m[1].trim().toLowerCase().replace(/:\d+$/, '');
};

/**
 * WHOIS lookup for an IP address. Starts at the detected RIR and follows
 * referrals between RIRs. Returns { text, server } or null.
 */
const ipWhois = async (ip) => {
    let server = detectRIR(ip).whoisServer;
    const visited = new Set();

    for (let hop = 0; hop < 3; hop++) {
        if (visited.has(server)) break;
        visited.add(server);

        let resp;
        try {
            // ARIN: "n + <ip>" = network info, full detail, no multi-match list
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

// ============================================================
// WHOIS output formatting
// ============================================================

/** Trim legal boilerplate from a domain WHOIS response. */
const cleanDomainWhois = (text) => {
    const stopRe = /^\s*(NOTICE:|TERMS OF USE:|By submitting a query|The Registry database contains|For more information on Whois status codes|The data in this|Access to .*WHOIS|% *Terms and Conditions|URL of the ICANN Whois Inaccuracy)/i;
    const out = [];
    let lastUpdateLine = null;
    for (const line of text.split(/\r?\n/)) {
        if (/^>>> Last update of/i.test(line.trim())) { lastUpdateLine = line.trim(); continue; }
        if (stopRe.test(line)) break;
        out.push(line);
    }
    // Collapse 3+ blank lines and trim
    let result = out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    if (lastUpdateLine) result += `\n\n${lastUpdateLine}`;
    return result;
};

/**
 * Case-insensitive multi-key field extractor for key/value WHOIS text.
 * Returns the first match, or all matches when `all` is true.
 */
const grabFields = (text, keys, all = false) => {
    // [ \t] only (not \s) so an empty value never slurps the next line
    const re = new RegExp(`^[ \\t]*(?:${keys.join('|')})[ \\t]*:[ \\t]*(\\S.*)$`, 'gim');
    const values = [];
    let m;
    while ((m = re.exec(text)) !== null) {
        const v = m[1].trim();
        if (v && !values.includes(v)) values.push(v);
        if (!all && values.length) break;
    }
    return all ? values : (values[0] || null);
};

/**
 * Build an informative, structured summary for an IP WHOIS response,
 * followed by the cleaned raw record.
 */
const formatIpWhois = (text, ip) => {
    const summary = [];
    const push = (label, value) => { if (value) summary.push(`${label}: ${value}`); };

    push('IP Address', ip);
    push('Network Range', grabFields(text, ['NetRange', 'inetnum', 'inet6num', 'IPv4 Address', 'IPv6 Address']));
    push('CIDR', grabFields(text, ['CIDR', 'route', 'route6'], true).join(', ') || null);
    push('Network Name', grabFields(text, ['NetName', 'netname']));
    push('Network Type', grabFields(text, ['NetType', 'status']));
    push('Organization', grabFields(text, ['Organization', 'OrgName', 'org-name', 'owner', 'descr']));
    push('Org ID', grabFields(text, ['OrgId', 'org', 'ownerid']));
    push('Address', grabFields(text, ['Address', 'address'], true).slice(0, 4).join(', ') || null);
    push('Country', grabFields(text, ['Country', 'country']));
    push('Origin AS', grabFields(text, ['OriginAS', 'origin', 'aut-num'], true).join(', ') || null);
    push('Abuse Contact', grabFields(text, ['OrgAbuseEmail', 'abuse-mailbox', 'abuse-c', 'e-mail']));
    push('Admin Contact', grabFields(text, ['OrgTechEmail', 'admin-c']));
    push('Registration Date', grabFields(text, ['RegDate', 'created']));
    push('Last Updated', grabFields(text, ['Updated', 'last-modified', 'changed']));
    push('Parent Network', grabFields(text, ['Parent', 'parent']));
    push('Registry Ref', grabFields(text, ['Ref', 'source']));

    // Clean raw record: drop comment/noise lines, collapse blanks
    const raw = text.split(/\r?\n/)
        .filter(l => !/^\s*[%#]/.test(l))
        .join('\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim();

    let out = '===== IP SUMMARY =====\n' + summary.join('\n');
    out += '\n\n===== FULL RECORD =====\n' + raw;
    return out;
};

// ============================================================
// RDAP formatting (fallback path)
// ============================================================

const vcardGet = (entity, field) => {
    if (!entity.vcardArray || !entity.vcardArray[1]) return null;
    const entry = entity.vcardArray[1].find(v => v[0] === field);
    if (!entry) return null;
    if (field === 'adr' && entry[1] && entry[1].label) return entry[1].label.replace(/\n/g, ', ');
    return entry[3] ? String(entry[3]).replace('tel:', '') : null;
};

function formatIpRdapAsRaw(rdap, ip) {
    const summary = [];
    const push = (label, value) => { if (value) summary.push(`${label}: ${value}`); };

    push('IP Address', ip);
    if (rdap.startAddress && rdap.endAddress) push('Network Range', `${rdap.startAddress} - ${rdap.endAddress}`);

    // CIDR blocks (cidr0 extension)
    if (Array.isArray(rdap.cidr0_cidrs) && rdap.cidr0_cidrs.length) {
        const cidrs = rdap.cidr0_cidrs
            .map(c => `${c.v4prefix || c.v6prefix}/${c.length}`)
            .join(', ');
        push('CIDR', cidrs);
    }

    push('IP Version', rdap.ipVersion);
    push('Network Name', rdap.name);
    push('Network Handle', rdap.handle);
    push('Network Type', rdap.type);
    push('Parent Handle', rdap.parentHandle);
    push('Country', rdap.country);

    // Origin AS (arin_originas0 extension)
    if (Array.isArray(rdap.arin_originas0_originautnums) && rdap.arin_originas0_originautnums.length) {
        push('Origin AS', rdap.arin_originas0_originautnums.map(a => `AS${a}`).join(', '));
    }

    // Entities: organization / abuse / admin / tech contacts (walk nested entities too)
    const contacts = [];
    const walkEntities = (entities) => {
        for (const entity of entities || []) {
            const roles = entity.roles || [];
            const fn = vcardGet(entity, 'fn');
            const email = vcardGet(entity, 'email');
            const tel = vcardGet(entity, 'tel');
            const adr = vcardGet(entity, 'adr');

            if (roles.includes('registrant')) {
                if (fn) push('Organization', fn);
                if (adr) push('Address', adr);
                if (email) push('Org Email', email);
                if (tel) push('Org Phone', tel);
            }
            if (roles.includes('abuse')) {
                if (fn) contacts.push(`Abuse Contact: ${fn}`);
                if (email) contacts.push(`Abuse Email: ${email}`);
                if (tel) contacts.push(`Abuse Phone: ${tel}`);
            }
            if (roles.includes('administrative')) {
                if (email) contacts.push(`Admin Email: ${email}`);
            }
            if (roles.includes('technical')) {
                if (email) contacts.push(`Tech Email: ${email}`);
            }
            if (entity.entities) walkEntities(entity.entities);
        }
    };
    walkEntities(rdap.entities);
    for (const c of contacts) { if (!summary.includes(c)) summary.push(c); }

    // Dates
    if (rdap.events) {
        for (const event of rdap.events) {
            if (event.eventAction === 'registration') push('Registration Date', event.eventDate);
            else if (event.eventAction === 'last changed') push('Last Updated', event.eventDate);
        }
    }

    // Status
    if (rdap.status && rdap.status.length > 0) push('Status', rdap.status.join(', '));

    // Remarks (often contain routing/usage notes)
    if (Array.isArray(rdap.remarks)) {
        for (const remark of rdap.remarks.slice(0, 2)) {
            if (remark.description && remark.description.length) {
                push('Remarks', remark.description.join(' ').slice(0, 200));
            }
        }
    }

    // Links
    if (rdap.links) {
        const selfLink = rdap.links.find(l => l.rel === 'self');
        if (selfLink && selfLink.href) push('RDAP URL', selfLink.href);
    }

    return summary.join('\n');
}

function formatRdapAsRaw(rdap) {
    const lines = [];

    // Domain basic info
    lines.push(`Domain Name: ${rdap.ldhName?.toUpperCase() || 'N/A'}`);
    if (rdap.handle) lines.push(`Registry Domain ID: ${rdap.handle}`);

    // Registrar info from entities
    if (rdap.entities) {
        for (const entity of rdap.entities) {
            const roles = entity.roles || [];

            if (roles.includes('registrar')) {
                const fn = vcardGet(entity, 'fn');
                if (fn) lines.push(`Registrar: ${fn}`);

                if (entity.links && entity.links[0] && entity.links[0].href) {
                    lines.push(`Registrar URL: ${entity.links[0].href}`);
                }

                const email = vcardGet(entity, 'email');
                if (email) lines.push(`Registrar Abuse Contact Email: ${email}`);

                const tel = vcardGet(entity, 'tel');
                if (tel) lines.push(`Registrar Abuse Contact Phone: ${tel}`);

                if (entity.publicIds) {
                    const ianaId = entity.publicIds.find(p => p.type === 'IANA Registrar ID');
                    if (ianaId) lines.push(`Registrar IANA ID: ${ianaId.identifier}`);
                }
            }
        }
    }

    // Dates
    if (rdap.events) {
        for (const event of rdap.events) {
            if (event.eventAction === 'registration') {
                lines.push(`Creation Date: ${event.eventDate}`);
            } else if (event.eventAction === 'expiration') {
                lines.push(`Registry Expiry Date: ${event.eventDate}`);
            } else if (event.eventAction === 'last changed') {
                lines.push(`Updated Date: ${event.eventDate}`);
            }
        }
    }

    // Status
    if (rdap.status && rdap.status.length > 0) {
        for (const status of rdap.status) {
            lines.push(`Domain Status: ${status}`);
        }
    }

    // Nameservers
    if (rdap.nameservers && rdap.nameservers.length > 0) {
        for (const ns of rdap.nameservers) {
            if (ns.ldhName) {
                lines.push(`Name Server: ${ns.ldhName.toUpperCase()}`);
            }
        }
    }

    // DNSSEC
    if (rdap.secureDNS) {
        const dnssec = rdap.secureDNS.delegationSigned ? 'signedDelegation' : 'unsigned';
        lines.push(`DNSSEC: ${dnssec}`);
    }

    // Query timestamp at the end
    const queryTime = new Date().toISOString();
    lines.push(''); // Empty line for spacing
    lines.push(`>>> Last update of RDAP database: ${queryTime} <<<`);

    return lines.join('\n');
}

// ============================================================
// Lookup orchestration: WHOIS first, RDAP fallback
// ============================================================

// Live IANA RDAP bootstrap (https://data.iana.org/rdap/dns.json), cached per process
let ianaRdapBootstrap = null;
const getIanaRdapServer = async (tld) => {
    try {
        if (!ianaRdapBootstrap) {
            const [json] = await httpGetJson('https://data.iana.org/rdap/dns.json', 15000);
            ianaRdapBootstrap = json;
        }
        if (ianaRdapBootstrap?.services) {
            for (const [tlds, urls] of ianaRdapBootstrap.services) {
                if (tlds.includes(tld)) return urls[0];
            }
        }
    } catch (e) {
        console.error('IANA RDAP bootstrap error:', e.message);
    }
    return null;
};

const rdapLookup = async (input) => {
    const target = normalizeInput(input);
    const ipType = isIP(target);

    if (ipType) {
        const rir = detectRIR(target);
        const url = `${rir.rdapServer.replace(/\/$/, '')}/ip/${target}`;
        const [json] = await httpGetJson(url);
        if (json && !json.errorCode) return [json, 'ip'];
        // Fallback to rdap.org bootstrap
        const [fallbackJson] = await httpGetJson(`https://rdap.org/ip/${target}`);
        if (fallbackJson && !fallbackJson.errorCode) return [fallbackJson, 'ip'];
    } else {
        const tld = extractTld(target);
        const tldEntry = rdapRegistry.find(e => e.tld === tld);

        if (tldEntry?.rdapServer) {
            const [json] = await httpGetJson(`${tldEntry.rdapServer.replace(/\/$/, '')}/domain/${target}`);
            if (json && !json.errorCode) return [json, 'domain'];
        }

        const [bootstrapJson] = await httpGetJson(`https://rdap.org/domain/${target}`);
        if (bootstrapJson && !bootstrapJson.errorCode) return [bootstrapJson, 'domain'];

        // Last resort: live IANA RDAP bootstrap discovery
        const ianaServer = await getIanaRdapServer(tld);
        if (ianaServer && ianaServer !== tldEntry?.rdapServer) {
            const [ianaJson] = await httpGetJson(`${ianaServer.replace(/\/$/, '')}/domain/${target}`);
            if (ianaJson && !ianaJson.errorCode) return [ianaJson, 'domain'];
        }
    }
    return [null, null];
};

/**
 * Lookup orchestration:
 *
 *   DOMAINS:  RDAP (primary)  -> WHOIS port 43 (fallback)
 *             RDAP is more reliable for domains (HTTPS, structured data,
 *             not blocked by port-43 firewalls).
 *
 *   IP/CIDR:  WHOIS port 43 only (no RDAP fallback).
 *             RIR WHOIS gives the richest raw records for IP networks.
 *
 * DOMAIN OPTIONS (engine override, domains only):
 *   engine = 'whois' → WHOIS port 43 first, RDAP as fallback
 *             (useful when RDAP data is stale, e.g. some .id extensions)
 *   engine = 'rdap'  → RDAP only, no WHOIS fallback
 *
 * Returns { raw, type, source } or null (= not found anywhere).
 */
const lookup = async (input, engine = null) => {
    const target = normalizeInput(input);
    const ipType = isIP(target);

    if (ipType) {
        // --- IP: WHOIS only (no RDAP fallback) ---
        try {
            const result = await ipWhois(target);
            if (result) {
                return {
                    raw: formatIpWhois(result.text, target),
                    type: 'ip',
                    source: `WHOIS (${result.server})`
                };
            }
        } catch (e) {
            console.error('WHOIS IP lookup error:', e.message);
        }
        return null;
    }

    // --- Domain: engine override --whois → WHOIS first ---
    if (engine === 'whois') {
        try {
            const result = await domainWhois(target);
            if (result) {
                return {
                    raw: cleanDomainWhois(result.text),
                    type: 'domain',
                    source: `WHOIS (${result.server})`
                };
            }
        } catch (e) {
            console.error('WHOIS domain lookup error:', e.message);
        }
        // WHOIS failed → still try RDAP so the user gets something
        console.log(`--whois failed, falling back to RDAP for: ${target}`);
        const [json] = await rdapLookup(target);
        if (json) {
            return { raw: formatRdapAsRaw(json), type: 'domain', source: 'RDAP (fallback)' };
        }
        return null;
    }

    // --- Domain: 1. RDAP (primary) ---
    try {
        const [json] = await rdapLookup(target);
        if (json) {
            return { raw: formatRdapAsRaw(json), type: 'domain', source: 'RDAP' };
        }
    } catch (e) {
        console.error('RDAP domain lookup error:', e.message);
    }

    // --- Domain: engine override --rdap → stop here, no WHOIS fallback ---
    if (engine === 'rdap') return null;

    // --- Domain: 2. WHOIS port 43 (fallback) ---
    console.log(`Falling back to WHOIS for domain: ${target}`);
    try {
        const result = await domainWhois(target);
        if (result) {
            return {
                raw: cleanDomainWhois(result.text),
                type: 'domain',
                source: `WHOIS fallback (${result.server})`
            };
        }
    } catch (e) {
        console.error('WHOIS domain lookup error:', e.message);
    }

    return null;
};

// Bot Commands
bot.start((ctx) => {
    const botName = process.env.BOT_NAME || "id Whois Bot";
    const welcomeMsg = process.env.START_MESSAGE
        ? process.env.START_MESSAGE.replace(/\{BOT_NAME\}|\$\{BOT_NAME\}/gi, botName)
        : `Welcome to ${botName} - RDAP Lookup Utility`;
    ctx.reply(welcomeMsg, {
        reply_parameters: { message_id: ctx.message.message_id }
    });
});

bot.on('message', async (ctx, next) => {
    if (!ctx.message || !ctx.message.text) return next();

    const text = ctx.message.text;
    const regex = /^\/whois(?:@\w+)?(?:\s+(.+))?$/;
    const match = text.match(regex);

    if (!match) return next();

    // If matches /whois or /whois@botname
    let input = match[1];

    if (!input) {
        const botName = process.env.BOT_NAME || "id Whois Bot";
        // Monospace examples via MarkdownV2 backticks
        const usage = [
            escapeMdV2(`🔍 ${botName} — Usage Guide`),
            '',
            escapeMdV2('Command:'),
            '`/whois <domain or IP address>`',
            '',
            escapeMdV2('Domain lookup (default: RDAP first, WHOIS fallback):'),
            '• `/whois example.com`',
            '• `/whois pandi.id`',
            '',
            escapeMdV2('Engine options (domains only):'),
            '• `-whois` ' + escapeMdV2(': query WHOIS (port 43) directly, skip RDAP.'),
            '  ' + escapeMdV2('Useful when RDAP data is stale (e.g. .id extensions).'),
            '  ' + escapeMdV2('Example:') + ' `/whois pandi.id -whois`',
            '• `-rdap` ' + escapeMdV2(': query RDAP only, no WHOIS fallback.'),
            '  ' + escapeMdV2('Example:') + ' `/whois example.com -rdap`',
            '',
            escapeMdV2('IP address lookup (always WHOIS via RIR, flags ignored):'),
            '• `/whois 8.8.8.8`',
            '• `/whois 2606:4700:4700::1111`'
        ].join('\n');
        return ctx.reply(usage, {
            parse_mode: 'MarkdownV2',
            reply_parameters: { message_id: ctx.message.message_id }
        });
    }

    // Parse engine option flags: -whois | -rdap
    // Also accept --whois / --rdap and Telegram's auto em-dash "—whois" / "—rdap".
    let engine = null;
    const flagMatch = input.match(/(?:^|\s)(?:-{1,2}|\u2014)(whois|rdap)\b/i);
    if (flagMatch) engine = flagMatch[1].toLowerCase();
    input = input.replace(/(?:^|\s)(?:-{1,2}|\u2014)\S+/g, ' ').trim();

    if (!input) {
        return ctx.reply("Please provide a domain or IP address, e.g. /whois example.com --whois", {
            reply_parameters: { message_id: ctx.message.message_id }
        });
    }

    const engineLabel = engine ? ` [engine: ${engine.toUpperCase()}]` : '';
    const loadingText = escapeMdV2(`⏳ Searching WHOIS data for: ${input}${engineLabel}...`);
    const loadingMsg = await ctx.reply(loadingText, {
        parse_mode: 'MarkdownV2',
        reply_parameters: { message_id: ctx.message.message_id }
    });

    try {
        const result = await lookup(input, engine);
        if (result) {
            let { raw, type, source } = result;

            // Keep the message under Telegram's 4096-char limit
            if (raw.length > MAX_OUTPUT_CHARS) {
                raw = raw.slice(0, MAX_OUTPUT_CHARS) + '\n... (output truncated)';
            }

            const inputType = type === 'ip' ? 'IP Address' : 'domain';
            const firstName = ctx.from.first_name || 'there';

            const header = escapeMdV2(`Hi ${firstName}, below is the whois result for ${inputType} ${input}`);
            const footer = escapeMdV2(`Source: ${source}`);

            // For MarkdownV2 code blocks, we should escape backslashes and backticks inside the block
            const escapedRaw = raw.replace(/([\\`])/g, '\\$1');

            const message = `${header}\n\`\`\`\n${escapedRaw}\n\`\`\`\n${footer}`;

            // Edit the loading message with the result
            await ctx.telegram.editMessageText(ctx.chat.id, loadingMsg.message_id, undefined, message, { parse_mode: 'MarkdownV2' });
        } else {
            const target = normalizeInput(input);
            const errorText = isIP(target)
                ? escapeMdV2(`❌ IP address not found: ${input} (WHOIS lookup failed).`)
                : escapeMdV2(`❌ Domain not found: ${input} (checked RDAP and WHOIS).`);
            await ctx.telegram.editMessageText(ctx.chat.id, loadingMsg.message_id, undefined, errorText, { parse_mode: 'MarkdownV2' });
        }
    } catch (e) {
        console.error('Command Error:', e);
        try {
            const internalErrorText = escapeMdV2('❌ An internal error occurred.');
            await ctx.telegram.editMessageText(ctx.chat.id, loadingMsg.message_id, undefined, internalErrorText, { parse_mode: 'MarkdownV2' });
        } catch (editError) {
            ctx.reply('❌ An internal error occurred.');
        }
    }
});

// Start Bot (only when run directly: `node index.js`)
if (require.main === module) {
    bot.launch().then(() => {
        console.log('Bot is running...');
    }).catch((err) => {
        console.error('Failed to launch bot:', err);
    });

    // Enable graceful stop
    process.once('SIGINT', () => bot.stop('SIGINT'));
    process.once('SIGTERM', () => bot.stop('SIGTERM'));
}

// Exported for testing
module.exports = { lookup, whoisQuery, domainWhois, ipWhois, rdapLookup };
