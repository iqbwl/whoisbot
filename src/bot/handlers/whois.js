const { BOT_NAME, MAX_OUTPUT_CHARS } = require('../../config');
const { escapeMdV2, escapeCodeBlock } = require('../../utils/telegram');
const { lookup } = require('../../services/lookupService');
const { isIP, normalizeInput } = require('../../utils/validator');

function getUsageMessage() {
    const botName = process.env.BOT_NAME || BOT_NAME;
    return [
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
}

async function handleWhois(ctx, next) {
    if (!ctx.message || !ctx.message.text) return next();

    const text = ctx.message.text;
    const regex = /^\/whois(?:@\w+)?(?:\s+([\s\S]+))?$/;
    const match = text.match(regex);

    if (!match) return next();

    let input = match[1];

    if (!input || !input.trim()) {
        return ctx.reply(getUsageMessage(), {
            parse_mode: 'MarkdownV2',
            reply_parameters: { message_id: ctx.message.message_id }
        });
    }

    input = input.trim();

    let engine = null;
    const flagMatch = input.match(/(?:^|\s)(?:-{1,2}|\u2014)(whois|rdap)\b/i);
    if (flagMatch) engine = flagMatch[1].toLowerCase();
    input = input.replace(/(?:^|\s)(?:-{1,2}|\u2014)\S+/g, ' ').trim();

    if (!input) {
        return ctx.reply("Please provide a domain or IP address, e.g. /whois example.com -whois", {
            reply_parameters: { message_id: ctx.message.message_id }
        });
    }

    const engineLabel = engine ? ` [engine: ${engine.toUpperCase()}]` : '';
    const loadingText = escapeMdV2(`⏳ Searching WHOIS data for: ${input}${engineLabel}...`);

    let loadingMsg = null;
    try {
        loadingMsg = await ctx.reply(loadingText, {
            parse_mode: 'MarkdownV2',
            reply_parameters: { message_id: ctx.message.message_id }
        });
    } catch (sendErr) {
        console.error('Failed to send loading message:', sendErr.message);
    }

    try {
        const result = await lookup(input, engine);
        if (result) {
            let { raw, type, source } = result;

            if (raw.length > MAX_OUTPUT_CHARS) {
                raw = raw.slice(0, MAX_OUTPUT_CHARS) + '\n... (output truncated)';
            }

            const inputType = type === 'ip' ? 'IP Address' : 'domain';
            const firstName = ctx.from?.first_name || 'there';

            const header = escapeMdV2(`Hi ${firstName}, below is the whois result for ${inputType} ${input}`);
            const footer = escapeMdV2(`Source: ${source}`);
            const escapedRaw = escapeCodeBlock(raw);
            const message = `${header}\n\`\`\`\n${escapedRaw}\n\`\`\`\n${footer}`;

            if (loadingMsg) {
                await ctx.telegram.editMessageText(ctx.chat.id, loadingMsg.message_id, undefined, message, {
                    parse_mode: 'MarkdownV2'
                });
            } else {
                await ctx.reply(message, {
                    parse_mode: 'MarkdownV2',
                    reply_parameters: { message_id: ctx.message.message_id }
                });
            }
        } else {
            const target = normalizeInput(input);
            const errorText = isIP(target)
                ? escapeMdV2(`❌ IP address not found: ${input} (WHOIS lookup failed).`)
                : escapeMdV2(`❌ Domain not found: ${input} (checked RDAP and WHOIS).`);

            if (loadingMsg) {
                await ctx.telegram.editMessageText(ctx.chat.id, loadingMsg.message_id, undefined, errorText, {
                    parse_mode: 'MarkdownV2'
                });
            } else {
                await ctx.reply(errorText, {
                    parse_mode: 'MarkdownV2',
                    reply_parameters: { message_id: ctx.message.message_id }
                });
            }
        }
    } catch (e) {
        console.error('Command Error:', e);
        const internalErrorText = escapeMdV2('❌ An internal error occurred.');
        if (loadingMsg) {
            try {
                await ctx.telegram.editMessageText(ctx.chat.id, loadingMsg.message_id, undefined, internalErrorText, {
                    parse_mode: 'MarkdownV2'
                });
            } catch (editError) {
                ctx.reply('❌ An internal error occurred.');
            }
        } else {
            ctx.reply('❌ An internal error occurred.');
        }
    }
}

module.exports = {
    handleWhois
};
