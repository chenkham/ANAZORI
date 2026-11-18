# Anazori

PHP festival website with public event pages, participant accounts, reviewed payment screenshots, private tickets and an event-scoped organising studio.

## Local development

Requirements: PHP 8.2+ with PDO SQLite (or PDO MySQL), Fileinfo, OpenSSL, mbstring and DOM; Node.js 20+; Composer.

```sh
composer install
npm ci
npm run build
npm run serve
```

The preview opens on http://localhost:8088. Use `router.php` when starting PHP yourself: `php -S localhost:8000 router.php`. It supplies clean routes and prevents direct access to source and private data. Apache hosting uses `.htaccess`.

PHP reads environment variables and an optional private `anazori-config.php` beside `public_html`; it does not load `.env` files automatically. Use the [Hostinger deployment guide](docs/HOSTINGER.md) and `deploy/anazori-config.example.php` for anazori.ccsdu.in. Set a strong bootstrap password for a new installation, then change it through My account. Existing databases and staff accounts are retained. Google and SMTP settings are editable in Studio → Integrations.

## Event operations

1. A Super Admin assigns each coordinator to their event and grants permissions. The Event coordinator preset includes event publishing, payment review, ticket controls and expense submission. Select only the permissions each person needs. Existing accounts are not granted new permissions automatically.
2. In Events → Edit, expand **Passes, prices and capacity**, **Payment methods**, and **Registration form**. Add the actual receiving accounts and publish the event when registration is ready. Paid options cannot be purchased without an active payment method.
   Joystick has **Games and competitions**. Save the confirmed games, then associate a pass with a game when it needs separate pricing or capacity. Registration and tickets retain the selected game even after labels change. Payment/ticket registers filter by game and include it in CSV exports.
3. Participants save their registration, use the displayed payment details, and upload a screenshot with a transaction reference and date. Places are held for one hour; screenshots submitted within that reservation retain the hold during review.
4. In Payments, open the registration, check the screenshot and confirm its reference and exact amount in the receiving account. Approving releases tickets. Request correction with a note when the evidence does not match. No screenshot recognition or automatic bank verification is claimed.
5. In Tickets, block or unblock with a reason. Blocking suspends entry. Unblocking restores the previous status, including a ticket already used. A full recorded refund voids tickets permanently.
6. Finance tracks approved registration receipts, actual refunds, budgets, expenses and other income. Reports compare event credits with the receiving accounts and export the event archive. Pending evidence is excluded from income. Refund forms record transfers already made outside the website; they never send money.

Use private directories outside `public_html` for payment screenshots and expense receipts. Back up these directories with the database. The JSON event archive contains evidence IDs and hashes, registration answers, account snapshots, reviews, budgets, expenses and ticket statuses; it does not contain the image files or QR secrets.

## Code and checks

See [Architecture](docs/ARCHITECTURE.md) for module ownership, states, permissions and deployment. Edit `src/` and run the build; do not hand-edit compiled files in `assets/2026/`.

```sh
php tests/manual-payments.php
node tests/manual-payment-browser.mjs
php tests/studio-access.php
php tests/studio-finance.php
php tests/game-google.php
node tests/release43.mjs
node tests/content-cast.mjs
node tests/supplied-scenes.mjs
```

Browser tests use separate temporary databases and private storage. They never use live participant records or send payments. Historical gateway integration tests remain available for retained gateway records; new checkout uses manual payment review.

The clean installation export and application migrations were also verified on MariaDB 11.4.10, including game/Google identity, manual-payment, event-access and finance invariants. `tests/mariadb-qa.mjs` uses an optional local portable MariaDB runtime; it is not included in the hosting upload.
