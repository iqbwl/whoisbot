const grabFields = (text, keys, all = false) => {
    if (!text) return all ? [] : null;
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

const formatIpWhois = (text, ip) => {
    if (!text) return '';
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

    const raw = text.split(/\r?\n/)
        .filter(l => !/^\s*[%#]/.test(l))
        .join('\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim();

    let out = '===== IP SUMMARY =====\n' + summary.join('\n');
    out += '\n\n===== FULL RECORD =====\n' + raw;
    return out;
};

module.exports = {
    grabFields,
    formatIpWhois
};
