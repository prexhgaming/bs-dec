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
| `message` | `236` | message id holding the archive (forwarded to read its `file_id`) |
| `file_id` | – | use a known Telegram `file_id`, skips the message lookup |
| `url` | – | download from any direct URL instead of Telegram |
| `require` | `arm64-v8a,armeabi-v7a` | ABIs that must be found |
| `skip_asset_packs` | `true` | don't extract `*_mpk` / asset-pack APKs |
| `list_only` | `false` | only list what the bot can see, don't download |
| `notify` | `false` | post the report back into the chat |

`list_only` is the quickest sanity check that the bot can see the chat at all.

## Secrets

Repository secrets (Settings → Secrets and variables → Actions):

| secret | required | what it is |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | yes | the bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_API_ID` | for big files | `api_id` from <https://my.telegram.org> |
| `TELEGRAM_API_HASH` | for big files | `api_hash` from <https://my.telegram.org> |

### Why `api_id` / `api_hash` are needed

Telegram's **cloud** Bot API only lets a bot download ~20 MB (`getFile` answers
`400: Bad Request: file is too big`). The Blood Strike archive is ~640 MB. So the
workflow starts a self-hosted Bot API server in Docker:

```bash
docker run -d -p 127.0.0.1:8081:8081 \
  -e TELEGRAM_API_ID -e TELEGRAM_API_HASH -e TELEGRAM_LOCAL=1 \
  -v /tmp/tg-bot-api:/var/lib/telegram-bot-api \
  aiogram/telegram-bot-api:latest
```

and points the scripts at it with `TELEGRAM_API_BASE=http://127.0.0.1:8081`.
Local mode raises the download limit to 2000 MB. Without the two secrets the run
falls back to the cloud API and stops with a message explaining exactly this.

## Local use

```bash
export TELEGRAM_BOT_TOKEN='<token>'

# what can the bot see in the chat? (metadata only, nothing is downloaded)
python scripts/tg_fetch.py --chat 9117250551 --list-only --require-suffix .xapk,.zip

# fetch (needs a local Bot API server for files over 20 MB)
python scripts/tg_fetch.py --chat 9117250551 --message 236 --out-dir work

# unpack + check the ABIs
python scripts/inspect_apks.py work/com.netease.newspike_*.xapk \
  --out-dir work/unpacked --require arm64-v8a,armeabi-v7a --keep-extracted
```

Offline tests: `python -m unittest discover -s tests -v`.

Exit codes: `0` ok · `1` fetch/ABI failure · `2` usage or unreadable archive.

## Pitfalls worth knowing

- **`getUpdates` consumes updates.** A scan marks everything it read as confirmed,
  so the next scan finds nothing. Prefer `--message`/`--file-id`; those go through
  `forwardMessage`, which reads chat history and does not drain updates. The
  forward is deleted again right after the `file_id` is read.
- A bot only sees messages in chats it is a member of, and `getFile` links expire,
  so resolve the `file_id` per run rather than caching a download URL.
- Artifacts of a 640 MB archive are large: `skip_asset_packs` (default) and
  `compression-level: 0` keep the upload reasonable.
