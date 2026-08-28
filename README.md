# id Whois Bot (WHOIS + RDAP Fallback)

A powerful and lightweight Telegram bot for WHOIS lookups with a **hybrid engine**:

- **Domains** → **RDAP primary** (HTTPS, structured, firewall-friendly), WHOIS port 43 fallback.
- **IP addresses** → **WHOIS (RIR, port 43) only** — richest raw records, no RDAP fallback.

Provides structured, clean, and informative data for both domain names and IP addresses.

## Features

- **Domain lookups via RDAP first**: Resolution order: local `rdap-registry.json` → `rdap.org` bootstrap → live IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`). If all RDAP sources fail, falls back to classic WHOIS:
  - Registry WHOIS server resolved from a bundled static list (`whois-servers.json`, ~1,450 TLDs from the IANA root zone DB) with longest-suffix matching (`web.id` → `whois.id`); live `whois.iana.org` discovery only for TLDs missing from the list.
  - Follows `Registrar WHOIS Server:` referrals for registrar-level detail (thin registries like `.com`/`.net`).
- **IP lookups via WHOIS only (IPv4/IPv6)**: Detects the correct RIR (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC), queries port 43 directly, and follows inter-RIR referrals automatically. No RDAP fallback — requires outbound TCP port 43 access.
- **Informative IP Output**: IP lookups return a structured **IP SUMMARY** (network range, CIDR, network name/type, organization, address, country, origin AS, abuse/admin contacts, dates) followed by the full raw RIR record.
- **Clean Domain Output**: Legal boilerplate/disclaimers are stripped from domain WHOIS responses.
- **Source Transparency**: Every reply shows which server answered (e.g. `WHOIS (whois.verisign-grs.com → whois.markmonitor.com)` or `RDAP (fallback)`).
- **Telegram-Safe**: Output automatically truncated to stay within Telegram's 4096-character message limit.
- **Clean Interface**: Edits the "searching" message in-place to keep chat history tidy.
- **Configurable**: Customizable welcome message and easy environment setup.

## Lookup Flow

```
/whois <input>
    │
    ├─ IP address? ──► RIR WHOIS (port 43, follows referrals) ──► ok? ──► reply
    │                       │
    │                       └─ fail / not found ──► "IP address not found"
    │
    └─ Domain? ──► RDAP (registry JSON → rdap.org → IANA bootstrap) ──► ok? ──► reply
                        │
                        └─ all RDAP fail ──► WHOIS port 43
                                (whois-servers.json, longest suffix → registry → registrar referral)
                                    │
                                    └─ fails too ──► "Domain not found"
```

## Prerequisites

- Node.js (v14 or higher)
- NPM
- A Telegram Bot Token from [@BotFather](https://t.me/BotFather)
- Outbound TCP port 43 access (required for IP lookups and the `-whois` option; domain lookups via RDAP work without it)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/iqbwl/whoisbot.git
   cd whoisbot
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   - Copy `.env.example` to `.env`.
   - Add your `BOT_TOKEN`.
   ```env
   BOT_NAME="id Whois Bot"
   BOT_TOKEN=your_token_here
   START_MESSAGE="Welcome to {BOT_NAME} - RDAP Lookup Utility"
   ```

## Usage

Start the bot:
```bash
node index.js
```

### Running with PM2 (recommended for production)

```bash
cd whoisbot
npm install

# start
pm2 start index.js --name whoisbot

# auto-start on server reboot
pm2 startup   # run the command it prints
pm2 save
```

Day-to-day commands:

| Command | Description |
|---|---|
| `pm2 status` | Show process status |
| `pm2 logs whoisbot` | Tail logs |
| `pm2 restart whoisbot` | Restart (after editing code or `.env`) |
| `pm2 stop whoisbot` | Stop |
| `pm2 delete whoisbot` | Remove from PM2 |

Optional `ecosystem.config.js` for a tidier setup:

```js
module.exports = {
  apps: [{
    name: 'whoisbot',
    script: 'index.js',
    cwd: __dirname,
    autorestart: true,
    max_memory_restart: '200M',
    env: { NODE_ENV: 'production' }
  }]
};
```

Then: `pm2 start ecosystem.config.js && pm2 save`.

> `.env` is loaded automatically via `dotenv` since PM2 runs from the project directory. After editing `.env`, just `pm2 restart whoisbot`.

Commands in Telegram:
- `/start`: Show the welcome message.
- `/whois <domain or ip>`: Perform a lookup (domains: RDAP → WHOIS fallback; IPs: WHOIS only).
- `/whois` (no argument): Show the usage guide with all options.

Engine options (domains only):
- `-whois`: Query classic WHOIS (port 43) directly, skipping RDAP. Useful when RDAP data is stale (common with some registries, e.g. `.id` extensions). Falls back to RDAP if WHOIS fails.
- `-rdap`: Query RDAP only, with no WHOIS fallback.

> Single-dash flags are used because Telegram often auto-converts `--` into an em-dash (`—`). The bot still accepts `--whois`/`--rdap` and even `—whois`/`—rdap` for robustness.

For IP addresses these flags are ignored (IPs always use WHOIS via the RIR).

Example:
- `/whois google.com`
- `/whois pandi.id -whois`
- `/whois example.com -rdap`
- `/whois 8.8.8.8`
- `/whois 2606:4700:4700::1111`

## Using in Groups

The bot works in group chats out of the box — just invite it as a regular member (no admin rights needed).

- Responds to both `/whois <target>` and `/whois@YourBotName <target>` (Telegram appends `@botname` automatically when there are multiple bots in a group).
- Every reply is sent as a **reply to the requester's message**, so it's always clear who asked — the result header also greets the requester by first name.
- The "searching…" message is **edited in-place** into the final result, keeping group history clean (no double messages).
- Multiple members can query simultaneously; each request is processed independently.

**Privacy Mode**: keep BotFather's *Group Privacy* **enabled** (the default). The bot only needs `/command` messages, which are always delivered regardless of privacy mode — regular group chatter never reaches the bot. If you change the privacy setting while the bot is already in a group, kick and re-invite it for the change to take effect.

**Rate limits**: Telegram allows a bot roughly 20 messages/minute per group. Very busy groups may see slightly delayed responses.

## Development

The bot uses the following main components:
- `Telegraf`: Telegram Bot Framework.
- `net` (Node.js built-in): Raw WHOIS queries over TCP port 43.
- `Axios`: For RDAP API requests (fallback path).
- `whois-servers.json`: Static TLD → WHOIS server map (primary path; includes second-level zones like `web.id`, `co.uk`).
- `rdap-registry.json`: RDAP server mapping for specific TLDs (fallback path).

The lookup engine is exported for testing:
```js
const { lookup } = require('./index.js');
const result = await lookup('google.com');           // default: RDAP → WHOIS fallback
const result2 = await lookup('pandi.id', 'whois');   // force WHOIS engine
const result3 = await lookup('example.com', 'rdap'); // RDAP only
// result = { raw, type: 'domain'|'ip', source }
```

## License

MIT
