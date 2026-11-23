const { httpGetJson } = require('../utils/httpClient');
const { rdapRegistryMap } = require('../config/dataLoader');
const { detectRIR, extractTld, isIP, normalizeInput } = require('../utils/validator');

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
        if (rir?.rdapServer) {
            const url = `${rir.rdapServer.replace(/\/$/, '')}/ip/${target}`;
            const [json] = await httpGetJson(url);
            if (json && !json.errorCode) return [json, 'ip'];
        }
        const [fallbackJson] = await httpGetJson(`https://rdap.org/ip/${target}`);
        if (fallbackJson && !fallbackJson.errorCode) return [fallbackJson, 'ip'];
    } else {
        const tld = extractTld(target);
        const tldEntry = rdapRegistryMap.get(tld);

        if (tldEntry?.rdapServer) {
            const [json] = await httpGetJson(`${tldEntry.rdapServer.replace(/\/$/, '')}/domain/${target}`);
            if (json && !json.errorCode) return [json, 'domain'];
        }

        const [bootstrapJson] = await httpGetJson(`https://rdap.org/domain/${target}`);
        if (bootstrapJson && !bootstrapJson.errorCode) return [bootstrapJson, 'domain'];

        const ianaServer = await getIanaRdapServer(tld);
        if (ianaServer && ianaServer !== tldEntry?.rdapServer) {
            const [ianaJson] = await httpGetJson(`${ianaServer.replace(/\/$/, '')}/domain/${target}`);
            if (ianaJson && !ianaJson.errorCode) return [ianaJson, 'domain'];
        }
    }
    return [null, null];
};

module.exports = {
    getIanaRdapServer,
    rdapLookup
};
