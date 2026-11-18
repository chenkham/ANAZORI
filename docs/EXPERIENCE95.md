# Mobile experience, QR and mail update · 12 October 2026

The edited project is `the local Anazori project directory`. Upload its `src` folder as the document root and retain the existing production database, application key and uploads. Original changed files are preserved in `.local/backups/feature95`. No production deployment or live email test was performed.

## QR and tickets

Selecting a ticket category expands its linked payment QR into a modal, settles the QR with transform/opacity animation and slides the payment details into view. The amount and UPI address come from the currently selected category. Closing returns focus to that category. Existing save-before-payment behavior remains in place. Reduced motion skips the transition and the low tier uses a shorter transition.

Dashboard tickets use the same reveal pattern and fetch the existing authenticated ticket route without caching scan tokens. Escape, close, modified link clicks and ordinary navigation remain supported. Entry tickets and PDF downloads show the original Anazori wordmark; the PDF uses a 50 KB JPEG rendition of the original crop so transparent PNG support/GD is unnecessary. Source crop: `anazori-main-font.png`, x336/y908, 1490×344, resized to 900×208 and flattened on white at JPEG quality 92.

Payment QR images still require real coordinator configuration. A category with no linked payment QR remains unavailable for payment; the application never substitutes another category’s account or invents payment details.

## Adaptive motion

The existing native scroll timelines and previous background/rendering optimisations remain. Device memory, core count, touch pointer and Save Data choose an initial low/medium/high tier. These are hints, not a precise phone benchmark. During scrolling, a bounded 2.2-second foreground frame sample can reduce detail under sustained pressure. Sampling runs at most once per 15 seconds, with a 30-second change interval; repeated healthy samples can recover to the starting tier.

High retains the original motion. Medium reduces selected expensive perpetual SVG scenes and renders the festival card preview at up to 24 fps. Low replaces perpetual SVG decoration with its supplied still artwork, stops cloud/island/firefly decoration, removes selected blur and renders the card preview at up to 15 fps. Interactive motion, content and native scrolling remain available. Exported keepsake videos retain 30 fps. Hidden tabs, reduced motion and the explicit pause preference are respected.

The passport invitation now places the character and readable text side by side, followed by a full-width action area aligned with the text. Verified at 320, 390 and 700 pixels.

## PHP mail and hosting

| Purpose | Primary | Fallback |
|---|---|---|
| Verification/recovery OTP only | noreply1@ccsdu.in | noreply2@ccsdu.in |
| Approved tickets, rejected tickets, event reminders | noreply3@ccsdu.in | noreply4@ccsdu.in |

Delivery uses PHPMailer’s native `mail()` transport; no SMTP connection or mailbox password is used. Only approved ticket confirmations, ticket rejections and event reminders are queued. See MAIL101.md for reminder timing. Form, interest and contribution submissions do not send receipts. Older out-of-scope queued jobs are skipped. Owner quota/switch/failure alerts are the explicitly requested exception and always use the notification pair.

Sender allocations and shared limits are reserved atomically in the database before each attempt. Failures count against the budget, put that sender on a 15-minute cooldown, and retry the identical message through its paired address. Encrypted business jobs use leases, deduplication and bounded backoff. Alert jobs also use leases and remain queued when mail capacity is unavailable. Alerts are sent to `chenkhamchowlu@gmail.com` and describe configured quota exhaustion or transport rejection accurately.

Defaults are 90 shared attempts per rolling 24 hours, 8 per minute, and 45/day plus 4/minute per sender. OTP and alert headroom is preserved. Override through `ANAZORI_PHP_MAIL_DAILY_LIMIT`, `PER_MINUTE`, `SENDER_DAILY_LIMIT`, `SENDER_PER_MINUTE`, `OTP_1`, `OTP_2`, `NOTICE_1`, `NOTICE_2` (all prefixed `ANAZORI_PHP_MAIL_`). Increase limits only to fit the host’s actual allowance, including other applications sharing it.

**Required hosting setup:** authorise the four sender addresses and domain authentication, then schedule `php /ABSOLUTE/DOCUMENT/ROOT/includes/mail-worker95.php` every minute. The CLI-only worker ships with `src`; HTTP access is denied. `scripts/send-notifications.php` remains a compatible development entry point. Private setup examples and `deploy/HOSTINGER-SETUP.md` are updated. No live cron job or mailbox was provisioned from this laptop.

Changing From addresses cannot multiply a shared hosting quota. PHP returning true only means the host accepted the message, so later bounces or silent provider drops cannot trigger reliable failover. Host-wide rejection may delay the alert itself until the host resets. See [PHP mail documentation](https://www.php.net/manual/en/function.mail.php) and [Hostinger PHP-mail limits](https://www.hostinger.com/support/11393648-php-mail-limitation-explained-how-to-improve-email-delivery-with-smtp/).

## Security changes and bounds

All upload writers now share actual-byte size checks, strict multipart shape/upload-origin checks, MIME/extension matching, raster dimension limits, executable-content rejection and PDF signature/trailer/active-feature checks. Office uploads require ZipArchive and reject macros, embedded objects, traversal names, encryption, expansion bombs and oversized manifests. Documents remain private and are never extracted onto the server. Public SVG/script/HTML uploads are excluded.

Public media, payment proofs, registration drafts and finance receipts retain their existing permission/state checks, with additional upload rate limits and file containment checks. Download routes require owner or scoped staff access, verify hashes, reject links outside their storage root, and use no-store/nosniff/sandbox headers. Public upload directories use an extension allowlist, disabled execution and directory listing, and download/sandbox headers for PDFs. The development router follows the upload allowlist too.

CSRF verification rejects malformed tokens and explicit cross-site POSTs. Shared response headers restrict objects, base URLs, framing, microphone/geolocation/USB access, and enable HSTS on HTTPS responses. Existing session, password, SQL parameterisation, event scope and webhook verification remain.

These changes reduce tested attack paths; they cannot make a site immune to every attack. PDF keyword inspection is not a full malware scanner, and a document can still be harmful to the person opening it. Host antivirus/content disarm, patched PHP/dependencies, verified Apache rules, private filesystem permissions, TLS and backups remain operational responsibilities. ZipArchive is absent in this local PHP runtime; Office files are safely rejected here, and its ZIP inspection branch needs verification on the host with that extension enabled.

## Verification

- `php tests/mail-routing95.php`: isolated workflows, sender separation, failover, alert retries, leases, global quota and injection rejection. No real mail sent.
- `php tests/upload-security95.php`: actual size, dimensions, disguised executables, active/encoded PDF names, malformed uploads, CSRF and containment.
- `node tests/experience95.mjs`: isolated mobile tiers/runtime downgrade, responsive passport, QR selection/amount/UPI, authenticated ticket reveal, focus, reduced motion and branded PDF.
- `node tests/native-forms78.mjs --port=8195`: full draft/upload/edit/approval flow, private file access, event scope, duplicate transaction/capacity protection and exports.
- Ticket payment, finance and access suites plus PHP syntax checks. Visual artifacts are in `.local/feature95`; the PDF was rendered with Poppler and inspected.

The older `tests/manual-payments.php` suite predates contribution-only events and the one-ticket-per-registration contract and currently fails on those fixture assumptions; it was left unchanged. Current form/payment/finance suites exercise the supported flow. Browser tests use emulation and CPU pressure; physical low-end phones and live host mail delivery still require device/host verification. No zero-lag or guaranteed-inbox-delivery claim is made.

A diagnostic during verification displayed existing development database and Google OAuth credentials in the tool log. Rotate the local database password and Google OAuth client secret; preserve the application encryption key. These credentials were not sent by email or used in the isolated mail outbox tests.
