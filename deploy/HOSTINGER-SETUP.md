# ANAZORI: direct-folder upload to Hostinger

No ZIP extraction is needed. The website/document root is `src`.

## Upload these files

1. Upload the complete `src` folder, including hidden `.htaccess` and `.user.ini` files. Point the domain document root at this folder (or use the folder name you configure in hPanel). Keep the paths inside it unchanged.
2. Upload the two items **inside** `deploy/private` beside the hosted `src` folder: `anazori-config.php` and `anazori-private`. They must stay outside the document root. Use this production configuration, not the laptop-only `development` folder.
3. In phpMyAdmin, select a new, empty database and import `deploy/anazori-hostinger.sql`. Do not upload the SQL into `src` and do not import it over a database containing real registrations.

The resulting hosting layout is:

```text
domain directory/
  anazori-config.php
  anazori-private/
    application-key
    payment-proofs/
    registration-files/
    studio-receipts/
  src/                         <- website document root
    .htaccess
    .user.ini
    index.php
    api/
    assets/
    config/
    includes/
    vendor/
    uploads/media/
    coordinators/
    ...
```

Upload `src` and the private setup above. The other local folders (`frontend`, `scripts`, `tests`, `development`, `node_modules`, `.local`, `data`, `legacy`, `docs`, `output`, `scratch`, `tmp` and `artifacts`) are development or recovery material; they are not needed on the host. Existing ZIPs are retained only as local backups under `.local/packages-before-layout91`.

## Hosting configuration

- PHP 8.2 or newer, with PDO MySQL, cURL, mbstring, OpenSSL, Fileinfo and DOM. Set `max_input_vars` to at least 3000. The included `.user.ini` supplies upload/input defaults; verify hPanel overrides if any.
- The supplied production configuration contains the owner-provided MySQL credentials. Compare database name and username with the **full** values shown by hPanel; if a prefix is added, update `ANAZORI_DB_NAME` and `ANAZORI_DB_USER`. The configured host is `localhost`. The remote connection has not been verified from this laptop.
- Email uses native PHP `mail()` with no SMTP connection or password. Authorise `noreply1@ccsdu.in` and `noreply2@ccsdu.in` for OTP, and `noreply3@ccsdu.in` and `noreply4@ccsdu.in` for approved ticket confirmations, ticket rejection notices, event reminders and owner failover alerts. Verify sender permissions and SPF/DKIM/DMARC with the domain/host.
- All four addresses share the hosting account’s PHP-mail allowance. The private configuration defaults to 90 attempts per rolling 24 hours and 8 per minute, with OTP/alert headroom. Each sender has its own configured allocation and cooldown. These are application limits, not four independent provider quotas. Confirm the actual hosting limit before increasing them.
- Create an hPanel cron job every minute: `php /ABSOLUTE/DOMAIN/PATH/src/includes/mail-worker95.php`. Use the real PHP binary and document-root path shown by the host. The CLI-only worker ships in `src`; opening it over HTTP is denied. It processes ticket approvals, rejections, event reminders and pending quota/switch alerts to `chenkhamchowlu@gmail.com`.
- If PHP accepts mail and the provider later bounces/discards it, the application cannot detect that from `mail()` alone. A host-wide rejection can also delay the owner alert; pending alerts retry after capacity returns. Validate one live OTP and one notification on the deployed host.
- Enable PHP ZipArchive for DOCX/XLSX/PPTX uploads. Without it, Office documents are rejected with a request to use PDF. Antivirus/content disarm can be added at the host for deeper document scanning.
- Existing Google credentials are preserved. Confirm `https://anazori.ccsdu.in/oauth.php` as an authorised redirect URI in Google Cloud Console. A fresh Google sign-in creates a participant and collects their full name; later sign-ins open their dashboard.
- PHP needs write access to `src/uploads/media` and the private `anazori-private` storage folders. Keep the private key/config confidential and outside `src`. Use directories 700 and files 600 where supported; avoid 777.

There is no separate storage service to connect. Payment screenshots, ID documents and registration attachments use the private folders; public images use `src/uploads/media`. Back up MySQL, both upload locations and the existing application key together.

## Data and launch

The clean SQL retains the two organiser/staff accounts, event configuration, forms, published content and public media. Participant accounts, registrations, tickets, drafts, submitted documents, OTP history and mail queue were reset. The recovery backup remains in `.local/participant-reset90` on the laptop.

Before opening registration, use Studio's readiness checks and verify one live OTP, Google sign-in, paid/free registration, proof upload and coordinator approval on the deployed domain. These checks depend on real hosting credentials and cannot be completed from this laptop.

Paper Presentation currently has two paid ticket categories and one linked QR. Its coordinator must link the second category's QR before accepting payment for it. Existing configuration is preserved.

For future code updates, retain the production database, key and uploads. Re-importing the clean SQL resets data and is not an upgrade procedure.
