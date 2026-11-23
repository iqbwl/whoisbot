const { createBot } = require('./src/bot/bot');
const { lookup } = require('./src/services/lookupService');
const { whoisQuery, domainWhois, ipWhois } = require('./src/services/whoisClient');
const { rdapLookup } = require('./src/services/rdapClient');

const bot = createBot();

if (require.main === module) {
    bot.launch().then(() => {
        console.log('Bot is running...');
    }).catch((err) => {
        console.error('Failed to launch bot:', err);
    });

    // Graceful stop
    process.once('SIGINT', () => bot.stop('SIGINT'));
    process.once('SIGTERM', () => bot.stop('SIGTERM'));
}

module.exports = {
    bot,
    lookup,
    whoisQuery,
    domainWhois,
    ipWhois,
    rdapLookup
};
