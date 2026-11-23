const { BOT_NAME, START_MESSAGE } = require('../../config');

function handleStart(ctx) {
    const botName = process.env.BOT_NAME || BOT_NAME;
    const welcomeMsg = (process.env.START_MESSAGE || START_MESSAGE)
        .replace(/\{BOT_NAME\}|\$\{BOT_NAME\}/gi, botName);

    return ctx.reply(welcomeMsg, {
        reply_parameters: { message_id: ctx.message.message_id }
    });
}

module.exports = {
    handleStart
};
