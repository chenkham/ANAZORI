> Current workflow (6 October 2026): new registrations use event-specific payment methods and screenshot review. See [README](README.md) and [Architecture](docs/ARCHITECTURE.md). Gateway instructions below apply only to retained historical records.

# Festival deployment

Current hosting package: follow [Hostinger upload and database setup](deploy/HOSTINGER-SETUP.md). PHP mail uses noreply1@ccsdu.in and noreply2@ccsdu.in for verification/recovery OTPs, and noreply3@ccsdu.in and noreply4@ccsdu.in for approved tickets, rejected tickets and event reminders. Schedule the CLI mail worker every minute. No form submission receipts are sent. See [current email setup](MAIL101.md). Sending limits remain subject to the hosting account allowance.

This project has not been load-tested on production hosting. Local browser checks and file sizes do not establish capacity for thousands of simultaneous visitors. Plan for the festival's short registration burst as well as ordinary browsing, and test the actual host before opening registration.

Use a production web server with the host's supported PHP runtime and process manager. PHP-FPM exposes worker limits such as `pm.max_children`; ask the host for the real worker, CPU, memory, disk-I/O and bandwidth limits rather than selecting a plan by visitor count alone. PHP's `php -S` server is a development preview and is unsuitable for a public launch. [PHP-FPM configuration](https://www.php.net/manual/en/install.fpm.configuration.php), [PHP development-server limitations](https://www.php.net/manual/en/features.commandline.webserver.php).

The working local database and Hostinger package use MySQL/InnoDB. The clean SQL export includes the current schema, forms and staff accounts, with participant records removed. Supply the real hPanel database credentials in the private configuration; changing the driver alone does not migrate data. SQLite remains available for isolated development checks. The application's shared transaction-lock row can still serialize writes, so test expected registration traffic on the actual host. [InnoDB locking](https://dev.mysql.com/doc/refman/8.4/en/innodb-locking.html).

Set `ANAZORI_APP_ENV=production` and configure the public HTTPS origin, SMTP, Google sign-in and payment credentials using the existing setup guides. Preserve the database, uploaded media and application encryption key across releases. Restore a backup on staging before launch. Keep local databases, QA artifacts and backups out of the published upload.

The reversible performance changes in this revision are deliberately narrow:

- `.htaccess` enables gzip for static CSS, JavaScript and SVG when Apache's module is available. It fills static SVG, JavaScript, WebM and audio expiry gaps. Hashed build chunks and randomly named CMS uploads receive a one-year immutable policy; entry CSS/JS retain shorter caching and need a new release query version when changed. These additions match static filenames, including excluding PHP-generated private ticket SVGs. [Apache compression](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html), [expiry rules](https://httpd.apache.org/docs/2.4/mod/mod_expires.html).
- `cms_unpack()` reuses its code-defined schema during each request. Content records remain live database reads. This does not introduce shared CMS, user or integration caching.
- The originals are saved in `.local/world-before/performance/`. The PHP file passes syntax validation. Apache modules, `.htaccess` permissions, response headers and production throughput still need validation on the actual host.

Configure a CDN for public static `/assets/` and `/uploads/media/` files only. Bypass dynamic routes and APIs, including clean URLs such as `/events` and `/event/...`. Public PHP pages contain personalised navigation, and event pages can embed session CSRF tokens. Never use a cache-everything rule for account, checkout, dashboard, ticket, OAuth, studio, webhook or registration responses. Check cache headers and content encoding on static files, and confirm that private pages and generated downloads still use their existing no-store policy. An Nginx host needs equivalent server configuration because it does not read this Apache file.

Media sizes measured on 2 October 2026:

| Existing file | Bytes | Estimated transfer for 1,000 full cold downloads |
| --- | ---: | ---: |
| `hero-sound.mp4` | 4,241,090 | 4.24 GB |
| `hero-loop.mp4` | 3,992,030 | 3.99 GB |
| Clash variable WOFF2 | 29,432 | 29.4 MB |

These are arithmetic estimates using decimal units, not measured traffic or simultaneous bandwidth. Streaming ranges, partial viewing and browser/CDN caches change the actual transfer. Add other images, audio and interactive assets to the budget. On ordinary phones, verify the poster fallback, reduced motion, data-saving behaviour, off-screen pausing and touch navigation. Keep expensive graphics optional and check an actual mid-range phone on a slow connection.

Use isolated staging data and provider-approved sandbox credentials for load testing. Ramp browsing through 10, 25, 50 and 100 concurrent users, then the expected launch burst. Test the public routes together with the following critical journeys:

- Account creation/sign-in, email verification and recovery, with the existing rate limits respected.
- `/api/interest.php` registration/interest submissions, including retries and duplicate acknowledgements.
- `/checkout.php` and `/api/checkout.php`, including simultaneous requests for the final available passes.
- `/api/payment.php`, `/payment-return.php` and `/api/webhook.php`, covering cancellation, delayed confirmation, retries and duplicate callbacks.
- `/dashboard.php`, `/ticket.php` and PDF/QR downloads; `/api/checkin.php` with the separate volunteer app when ready.

Record throughput, p95/p99 latency, HTTP errors, database lock waits, PHP-worker saturation and CDN hit rate. Verify that capacities, amounts, ticket issuance and check-in remain correct under concurrency. External gateway and SMTP quotas are separate limits. Only claim production capacity after these measurements; changing visual effects or caching assets alone does not verify it.
