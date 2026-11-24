# WhoisBot

Telegram bot for domain and IP WHOIS lookups using a hybrid RDAP/WHOIS engine:

- **Domains**: RDAP (HTTPS) primary with WHOIS (TCP 43) fallback.
- **IP addresses**: Direct RIR WHOIS (TCP 43) with automatic referral chasing.

## Features

- **Domain lookups**: Resolves RDAP via local registry, `rdap.org`, and IANA bootstrap. Falls back to port 43 WHOIS using static server mappings (`whois-servers.json`) and follows registrar referrals.
- **IP lookups**: Routes IPv4/IPv6 to the appropriate RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC) over port 43, returning a structured summary followed by the raw record.
- **Telegram friendly**: Strips legal boilerplate, truncates output under 4096 characters, and edits the loading message in-place.
- **Engine overrides**: Supports `-whois` (force classic WHOIS) and `-rdap` (force RDAP only).

## Prerequisites

- Node.js 18 or higher
- Outbound TCP port 43 access (required for WHOIS queries)
- Telegram Bot Token from [@BotFather](https://t.me/BotFather)

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   ```
   Set your `BOT_TOKEN` in `.env`:
   ```env
   BOT_NAME="id Whois Bot"
   BOT_TOKEN=your_token_here
   START_MESSAGE="Welcome to {BOT_NAME} - RDAP Lookup Utility"
   ```

3. Run:
   ```bash
   # Direct
   node index.js

   # Production (PM2)
   pm2 start index.js --name whoisbot
   ```

## Testing

Run unit tests via Node's native test runner:

```bash
npm test
```

## Telegram Usage

- `/start`: Display welcome message.
- `/whois <domain or ip>`: Perform lookup.
- `/whois`: Display usage guide.

Flags (domains only):
- `/whois example.com -whois` - Query port 43 directly, skipping RDAP.
- `/whois example.com -rdap` - Query RDAP only, no WHOIS fallback.

## Project Structure

```
├── rdap-registry.json    # Static RDAP endpoint mappings
├── whois-servers.json    # Static TLD -> WHOIS server mappings
├── src/
│   ├── bot/              # Telegram bot instance and command handlers
│   ├── config/           # Environment config, constants, data loader (Map O(1))
│   ├── formatters/       # Response cleaners for domain & IP output
│   ├── services/         # TCP WHOIS client, RDAP client, lookup orchestrator
│   └── utils/            # Normalization, IP validation, MarkdownV2 helpers
├── tests/                # Unit tests (node:test)
├── index.js              # Application entry point & exports
└── package.json
```

## Module API

The lookup engine can also be imported as a library:

```js
const { lookup } = require('./index.js');

// Default: RDAP -> WHOIS fallback
const res1 = await lookup('google.com');

// Force WHOIS engine
const res2 = await lookup('pandi.id', 'whois');

// IP lookup (WHOIS via RIR)
const res3 = await lookup('1.1.1.1');
```

## License

This project is open-source and available under the terms of the [MIT License](LICENSE).
