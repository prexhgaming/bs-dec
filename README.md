# bs-dec

Pull the Blood Strike archive out of a **Telegram chat**, unpack it, and prove
which ABIs (32-bit `armeabi-v7a` / 64-bit `arm64-v8a`) are actually inside the
APKs. Everything runs on GitHub Actions; the scripts are plain Python 3 with no
dependencies outside the standard library.

## What it does

1. `scripts/tg_fetch.py` asks the bot for the archive and streams it to `work/`.
2. `scripts/inspect_apks.py` unzips it (including nested archives) and scans every
   `.apk` for `lib/<abi>/*.so`.
3. The run **fails** when an ABI in `require` (default `arm64-v8a,armeabi-v7a`)
   is missing, and writes `abi_report.json` + `abi_report.md` (also into the job
   summary, optionally back to the chat).

## Run it

Actions → **Blood Strike ABI check** → *Run workflow*.

| input | default | meaning |
| --- | --- | --- |
| `chat` | `9117250551` | chat id, `@username` or `t.me` link |
| `message` | `241` | message id holding the archive (forwarded to read its `file_id`) |
| `parts` | – | **split mode:** message ids of the <20 MB parts, e.g. `241-274` (needs no `api_id`) |
| `sha256` | – | expected sha256 of the assembled archive (parts mode) |
| `file_id` | – | use a known Telegram `file_id`, skips the message lookup |
| `url` | – | download from any direct URL instead of Telegram |
| `require` | `arm64-v8a,armeabi-v7a` | ABIs that must be found |
| `skip_asset_packs` | `true` | don't extract `*_mpk` / asset-pack APKs |
| `list_only` | `false` | only list what the bot can see, don't download |
| `notify` | `false` | post the report back into the chat |

`list_only` is the quickest sanity check that the bot can see the chat at all.

## The 20 MB problem, and the three ways around it

Telegram's **cloud** Bot API will not hand a bot a file bigger than ~20 MB
(`getFile` replies `400: Bad Request: file is too big`). The Blood Strike archive
is ~640 MB, so it cannot be pulled in one piece without help:

| route | needs | trade-off |
| --- | --- | --- |
| **A. parts** (default here) | nothing but the bot token | you split the file and send the parts; CI reassembles them and checks the sha256 |
| **B. self-hosted Bot API** | `api_id` + `api_hash` | one-time setup, then any size in one go (limit 2000 MB) |
| **C. direct URL** | any file host | no Telegram at all; `url:` input |

### A. Parts mode (no `api_id`)

Split the archive into chunks under 20 MB and send them to the bot in order:

```bash
split -b 19M -d --additional-suffix=.part com.netease.newspike.xapk bs.part   # bs.part00 ... bs.part34
```

Send `bs.part00`, `bs.part01`, … to the bot (or into the chat), note the message
ids, then run the workflow with `parts: 241-275`. The script downloads every part
through the ordinary cloud API, concatenates them in the given order into one
file, verifies `sha256` when you supply it, and deletes the parts again.
On the command line it is the same:

```bash
python scripts/tg_fetch.py --chat 9117250551 --parts 241-275 \
  --name com.netease.newspike.xapk --sha256 <hex> --out-dir work
```

Range syntax: `241-275`, `241,242,243`, `241 242 243`, or a mix (`241-250,255`).

### B. Self-hosted Bot API (needs `api_id`/`api_hash`)

`api_id`/`api_hash` are not an approval or a paid plan: they are the two numbers
that identify an **API client application** — the same pair the official
Telegram client uses. Everyone who runs any Telegram client library (Telethon,
Pyrogram, a custom bot server) has them. You get them free at
<https://my.telegram.org> → *API development tools*, by logging in with your
phone number. The standard Bot API cloud server simply refuses >20 MB files, and
only a server *you* run may raise that limit — which is why it asks for a
client identity. Add them as repo secrets and the workflow does this by itself:

```bash
docker run -d -p 127.0.0.1:8081:8081 \
  -e TELEGRAM_API_ID -e TELEGRAM_API_HASH -e TELEGRAM_LOCAL=1 \
  -v /tmp/tg-bot-api:/var/lib/telegram-bot-api \
  aiogram/telegram-bot-api:latest
```

then `TELEGRAM_API_BASE=http://127.0.0.1:8081`. Local mode allows 2000 MB.

### C. Direct URL

`url:` takes any `https://` link to the archive; nothing Telegram-specific is
used then.

## Secrets

Repository secrets (Settings → Secrets and variables → Actions):

| secret | required | what it is |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | yes | the bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_API_ID` | only for route B | `api_id` from <https://my.telegram.org> |
| `TELEGRAM_API_HASH` | only for route B | `api_hash` from <https://my.telegram.org> |

## Local use

```bash
export TELEGRAM_BOT_TOKEN='<token>'

# what can the bot see in the chat? (metadata only, nothing is downloaded)
python scripts/tg_fetch.py --chat 9117250551 --list-only --require-suffix .xapk,.zip

# single file (over 20 MB needs route B)
python scripts/tg_fetch.py --chat 9117250551 --message 241 --out-dir work

# split archive, no api_id needed
python scripts/tg_fetch.py --chat 9117250551 --parts 241-275 --out-dir work

# unpack + check the ABIs
python scripts/inspect_apks.py work/com.netease.newspike_*.xapk \
  --out-dir work/unpacked --require arm64-v8a,armeabi-v7a --keep-extracted
```

Offline tests: `python -m unittest discover -s tests -v` (50 tests, no network).

Exit codes: `0` ok · `1` fetch/ABI failure · `2` usage or unreadable archive.

## Pitfalls worth knowing

- **`getUpdates` consumes updates.** A scan marks everything it read as confirmed,
  so the next scan finds nothing. Prefer `--message`/`--file-id`; those go through
  `forwardMessage`, which reads chat history and does not drain updates. The
  forward is deleted again right after the `file_id` is read.
- A bot only sees messages in chats it is a member of, and `getFile` links expire,
  so resolve the `file_id` per run rather than caching a download URL.
- Parts must be sent in a way they arrive as separate documents, and the message
  ids must be given in the order the parts belong in — the script concatenates
  exactly what you list.
- GitHub's runner has plenty of disk (~14 GB free) for a 666 MB archive plus the
  extracted APKs, so no cleanup step is needed.
- Artifacts of a 640 MB archive are large: `skip_asset_packs` (default) and
  `compression-level: 0` keep the upload reasonable.
