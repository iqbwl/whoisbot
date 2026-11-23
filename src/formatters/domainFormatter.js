const cleanDomainWhois = (text) => {
    if (!text) return '';
    const stopRe = /^\s*(NOTICE:|TERMS OF USE:|By submitting a query|The Registry database contains|For more information on Whois status codes|The data in this|Access to .*WHOIS|% *Terms and Conditions|URL of the ICANN Whois Inaccuracy)/i;
    const out = [];
    const updateMatch = text.match(/^>>> Last update of.*<<</m);
    const lastUpdateLine = updateMatch ? updateMatch[0].trim() : null;

    for (const line of text.split(/\r?\n/)) {
        if (/^>>> Last update of/i.test(line.trim())) continue;
        if (stopRe.test(line)) break;
        out.push(line);
    }
    let result = out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    if (lastUpdateLine) result += `\n\n${lastUpdateLine}`;
    return result;
};

const vcardGet = (entity, field) => {
    if (!entity?.vcardArray || !entity.vcardArray[1]) return null;
    const entry = entity.vcardArray[1].find(v => v[0] === field);
    if (!entry) return null;
    if (field === 'adr' && entry[1] && entry[1].label) return entry[1].label.replace(/\n/g, ', ');
    return entry[3] ? String(entry[3]).replace('tel:', '') : null;
};

function formatRdapAsRaw(rdap) {
    if (!rdap) return '';
    const lines = [];

    lines.push(`Domain Name: ${rdap.ldhName?.toUpperCase() || 'N/A'}`);
    if (rdap.handle) lines.push(`Registry Domain ID: ${rdap.handle}`);

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

    if (rdap.status && rdap.status.length > 0) {
        for (const status of rdap.status) {
            lines.push(`Domain Status: ${status}`);
        }
    }

    if (rdap.nameservers && rdap.nameservers.length > 0) {
        for (const ns of rdap.nameservers) {
            if (ns.ldhName) {
                lines.push(`Name Server: ${ns.ldhName.toUpperCase()}`);
            }
        }
    }

    if (rdap.secureDNS) {
        const dnssec = rdap.secureDNS.delegationSigned ? 'signedDelegation' : 'unsigned';
        lines.push(`DNSSEC: ${dnssec}`);
    }

    const queryTime = new Date().toISOString();
    lines.push('');
    lines.push(`>>> Last update of RDAP database: ${queryTime} <<<`);

    return lines.join('\n');
}

module.exports = {
    cleanDomainWhois,
    formatRdapAsRaw,
    vcardGet
};
