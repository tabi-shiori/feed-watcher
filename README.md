# Feed Update Notifier

Lightweight 24/7 feed update watcher with iOS Bark (`timeSensitive` + `silence`) push notification support.

- All credentials and target feed IDs are loaded strictly from encrypted environment secrets (`BARK_KEY`, `WEREAD_COOKIE`, `MONITOR_TARGETS_JSON`).
- Deduplication state (`state.json`) stores only one-way SHA-256 hashes (`seen_hashes`), keeping all feed names and item titles private.
