require('dotenv').config();

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const BOT_NAME = process.env.BOT_NAME || 'id Whois Bot';
const START_MESSAGE = process.env.START_MESSAGE || 'Welcome to {BOT_NAME} - RDAP Lookup Utility';

const MAX_OUTPUT_CHARS = 3400; // keep under Telegram 4096 message limit
const IANA_WHOIS = 'whois.iana.org';

const RIRS = {
    ARIN: { name: 'ARIN', rdapServer: 'https://rdap.arin.net/registry', whoisServer: 'whois.arin.net' },
    RIPE: { name: 'RIPE NCC', rdapServer: 'https://rdap.db.ripe.net', whoisServer: 'whois.ripe.net' },
    APNIC: { name: 'APNIC', rdapServer: 'https://rdap.apnic.net', whoisServer: 'whois.apnic.net' },
    LACNIC: { name: 'LACNIC', rdapServer: 'https://rdap.lacnic.net/rdap', whoisServer: 'whois.lacnic.net' },
    AFRINIC: { name: 'AFRINIC', rdapServer: 'https://rdap.afrinic.net/rdap', whoisServer: 'whois.afrinic.net' }
};

module.exports = {
    BOT_TOKEN,
    BOT_NAME,
    START_MESSAGE,
    MAX_OUTPUT_CHARS,
    IANA_WHOIS,
    RIRS
};
