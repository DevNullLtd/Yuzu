# license_scan macOS fixtures

Real captures from this Mac (`braga.local`, macOS 26.6.2 `25G83`, arm64),
2026-10-26. Every file here is the raw bytes of a binary (`bplist00`)
`Info.plist` copied from an installed app bundle:

```
cat "/Applications/<App>.app/Contents/Info.plist" > <App>.Info.plist
```

No file was edited, trimmed or reconstructed. They back
`tests/unit/test_licensing_bplist.cpp`, which decodes them with
`agents/plugins/license_scan/src/licensing_bplist.hpp`.

## Files and expected values

The expected values are what `plutil -extract <key> raw -o - <file>` prints for
each key (the trailing newline is plutil's, not part of the value).

| File | Bundle | `CFBundleDisplayName` | `CFBundleName` | `CFBundleShortVersionString` | What it proves |
|---|---|---|---|---|---|
| `WhatsApp.Info.plist` | WhatsApp (3rd party, not App Store) | `U+200E` then `WhatsApp` (bytes `E2 80 8E` + `WhatsApp`) | `WhatsApp` | `26.41.28` | The one real UTF-16 (`0x6x`) string on this host: a leading LEFT-TO-RIGHT MARK that must round-trip byte-for-byte. |
| `Pages-Creator-Studio.Info.plist` | Pages Creator Studio (Mac App Store) | `Pages Creator Studio` | `Pages` | `15.1.1` | `CFBundleName` differs from `CFBundleDisplayName`; the license_scan macOS leg prefers the display name. |
| `Spotify.Info.plist` | Spotify (3rd party, not App Store) | `Spotify` | `Spotify` | `1.3.5.3058` | The smallest binary `Info.plist` on the host (2,045 bytes). |

## Notes

- Only the three keys above are read by the decoder; the rest of each plist is
  never interpreted.
- The WhatsApp display name carries the invisible `U+200E`. WhatsApp has no
  `_MASReceipt`, so it never becomes a `lic|` row and the committed macOS
  sample capture does not carry that character; the fixture exists to pin the
  UTF-16 decode.
- A full parity run over every binary `Info.plist` under `/Applications` (seven
  bundles on this host) against `plutil` was byte-identical, both as an unprivileged user and as root; that run is a
  verification step, not a committed test, because it depends on whatever apps
  the host has installed.
