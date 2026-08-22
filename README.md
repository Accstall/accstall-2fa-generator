# Accstall 2FA Generator

Browser-only TOTP generator. Paste a Base32 secret or an `otpauth://` URI and read the current 6-digit code plus the next 30-second window.

**Live demo:** [accstall.com/en/tools/2fa-generator](https://accstall.com/en/tools/2fa-generator)

## Privacy contract

1. **Runs in the browser.** Parse and generate in JavaScript. The paste is not sent to a backend, logged, or written to `localStorage` / `sessionStorage` / IndexedDB.
2. **No query-string secrets.** On load, `?secret=` is deleted with `history.replaceState` and a one-line warning is shown. Never put a TOTP secret in a shareable link.
3. **SHA1 / 6 / 30 only.** Compatible with Google Authenticator, Authy, and RFC 6238 SHA1 authenticators. otpauth URIs that ask for other digits, periods, or algorithms are **rejected**. A plausible wrong code is worse than no code.
4. Clipboard copy prefers `navigator.clipboard` and falls back to `document.execCommand('copy')`.

## Run locally

Open `index.html` in a browser (`file://` works). No build step.

This standalone copy uses the **device clock**. A wrong OS clock yields wrong codes. The [live Accstall page](https://accstall.com/en/tools/2fa-generator) can offset from a server clock (`GET /clock` → `{ "t": <unix_ms> }`). You can pass `{ clockUrl: '/clock' }` to `accstallTotp()` if you host that endpoint yourself.

```
npm test
```

RFC 4226 HOTP and RFC 6238 TOTP (6-digit) vectors must stay green. Do not tidy the SHA-1 / HMAC bit-twiddling without re-running them. `crypto.subtle` is intentionally not used so the page still works on plain HTTP / `file://`.

## Sister tools

- [accstall-account-line-parser](https://github.com/Accstall/accstall-account-line-parser)
- [accstall-cookie-converter](https://github.com/Accstall/accstall-cookie-converter)

## License

MIT
