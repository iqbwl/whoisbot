const { Telegraf } = require('telegraf');
const { BOT_TOKEN } = require('../config');
const { handleStart } = require('./handlers/start');
const { handleWhois } = require('./handlers/whois');

function createBot() {
    const token = process.env.BOT_TOKEN || BOT_TOKEN;
    const bot = new Telegraf(token);

    // Global error handler
    bot.catch((err, ctx) => {
        console.error(`Bot encountered an error for ${ctx?.updateType}:`, err);
    });

    // Register handlers
    bot.start(handleStart);
    bot.on('message', handleWhois);

    return bot;
}

module.exports = {
    createBot
};
