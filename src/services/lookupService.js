const { isIP, normalizeInput, extractTld } = require('../utils/validator');
const { ipWhois, domainWhois } = require('./whoisClient');
const { rdapLookup } = require('./rdapClient');
const { formatIpWhois } = require('../formatters/ipFormatter');
const { cleanDomainWhois, formatRdapAsRaw } = require('../formatters/domainFormatter');
const { rdapRegistryMap } = require('../config/dataLoader');

const lookup = async (input, engine = null) => {
    const target = normalizeInput(input);
    if (!target) return null;

    const ipType = isIP(target);

    if (ipType) {
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

    const tld = extractTld(target);
    const hasRdap = rdapRegistryMap.has(tld);
    const isWhoisPreferred = engine === 'whois' || tld === 'co' || tld === 'co.nl' || !hasRdap;

    if (isWhoisPreferred && engine !== 'rdap') {
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

        console.log(`WHOIS failed, falling back to RDAP for: ${target}`);
        const [json] = await rdapLookup(target);
        if (json) {
            return { raw: formatRdapAsRaw(json), type: 'domain', source: 'RDAP (fallback)' };
        }
        return null;
    }

    try {
        const [json] = await rdapLookup(target);
        if (json) {
            return { raw: formatRdapAsRaw(json), type: 'domain', source: 'RDAP' };
        }
    } catch (e) {
        console.error('RDAP domain lookup error:', e.message);
    }

    if (engine === 'rdap') return null;

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

module.exports = {
    lookup
};
