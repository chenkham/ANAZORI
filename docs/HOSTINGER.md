# Deploy Anazori at anazori.ccsdu.in

This project runs directly on PHP with PDO MySQL. Hostinger does not need Node.js: the browser bundles and Composer libraries are already built. Google sign-in and the database connection need the real credentials for your accounts. They cannot be inferred from the domain name.

The current prepared files, local phpMyAdmin access, event form controls and remaining account setup are listed in [LAUNCH-CHECKLIST.md](LAUNCH-CHECKLIST.md). A private production configuration with supplied Google credentials and a generated bootstrap password is now at `the private production configuration file`; fill its hosting database values, set the production Google client, and upload it above `public_html` as `anazori-config.php`.

## 1. Domain and PHP

Add `anazori.ccsdu.in` to the intended Hostinger website, point its DNS to that website, and enable its SSL certificate. Use PHP 8.2 or later with `pdo_mysql`, `mbstring`, `fileinfo`, `openssl`, `dom`, `curl` and `json` enabled. Keep `.htaccess` in the website's document root. Requests to this production domain redirect to HTTPS.

Upload the contents of `deploy/anazori-public-html.zip` into that domain's document root, normally `public_html`. Extract it there. The archive contains PHP, compiled browser assets, public media and Composer dependencies. Do not upload `.local`, local SQLite databases, tests, `node_modules`, raw animation downloads or a private configuration file into this directory. If your domain uses a different directory, adjust the private configuration location described below.

## 2. Create and import the database

In hPanel, create a database and its database user for this website. Save the **complete** database name and username including Hostinger's account prefix, and the password you set. The database host for a locally hosted connection is `localhost`, port `3306`; Hostinger uses MariaDB. [Hostinger database details](https://www.hostinger.com/support/1583226-which-database-management-system-is-used-at-hostinger/).

Open phpMyAdmin for that **new, empty database**, choose Import, and upload `deploy/anazori-hostinger.sql`. It creates the schema and imports the website's saved content. It deliberately contains no participant, staff-password, order, screenshot, budget, expense, integration credential or application records. Historical photos and committee content remain actual supplied public content. The visitor counter starts at zero. [Hostinger's import instructions](https://www.hostinger.com/support/1884149-how-to-import-a-database-with-phpmyadmin-in-hostinger/).

Do not reimport this installation file over a running festival database. Later updates use additive PHP schema migrations. Back up the live database before an update.

## 3. Save the private configuration

Copy `deploy/anazori-config.example.php` to the **parent directory of public_html** and rename it `anazori-config.php`. For example:

```
website-directory/
  anazori-config.php             private configuration
  anazori-private/               created by PHP; keep it private
  public_html/                  extracted website files
```

Replace the database-name, user and password placeholders with the values from hPanel. Set a new random bootstrap password of at least 20 characters. This is the first organiser sign-in password; it is not a database password. Never reuse the local preview password. The application refuses to connect when database credentials are missing.

The template fixes the origin at `https://anazori.ccsdu.in` and places the encryption key, payment screenshots and expense receipts outside the public directory. PHP must be able to create/write `anazori-private`. Keep the private config and generated encryption key readable only by your hosting account. Back up that key together with the database: encrypted integration settings need the same key after a restore.

If the domain's document root is nested differently, set `ANAZORI_PRIVATE_CONFIG` in the server environment to the private file's absolute path, or update the private file location in `config/runtime.php`. Keep the evidence directories outside the actual document root. Explicit environment variables override the private file.

## 4. First organiser sign-in

Open `https://anazori.ccsdu.in/login.php`. Sign in with the configured master email (`ANAZORI_SUPER_EMAIL` in `includes/platform.php`) and your new bootstrap password. Change it when prompted. Create named coordinator accounts, grant only the required permissions and assign their event IDs. A coordinator with no assigned events sees no event records.

## 5. Connect Google sign-in and signup

In the Google Cloud project for Anazori, configure Google Auth Platform branding/audience, then create an **OAuth client of type Web application**. Add:

| Setting | Exact value |
| --- | --- |
| Application homepage | `https://anazori.ccsdu.in/` |
| Authorized JavaScript origin | `https://anazori.ccsdu.in` |
| Authorized redirect URI | `https://anazori.ccsdu.in/oauth.php` |
| Privacy policy | `https://anazori.ccsdu.in/privacy.php` |
| Terms | `https://anazori.ccsdu.in/terms.php` |
| Authorized domain | Your verified parent domain, `ccsdu.in` |

Use only the `openid` and `email` scopes. Select an External audience and publish the app for the public festival. Google exempts these basic identity-only scopes from its usual test-user restrictions. Google requires the redirect URI to match exactly. [Google's server-side OAuth flow](https://developers.google.com/identity/protocols/oauth2/web-server), [audience rules](https://support.google.com/cloud/answer/15549945?hl=en), [production OAuth policies](https://developers.google.com/identity/protocols/oauth2/policies). Follow [the complete local and production setup guide](GOOGLE-SIGNIN.md) for the Console and Studio steps.

Save the client ID and client secret in **Studio → Integrations → Google**. Alternatively, fill the two Google values in the private config; nonempty private values override Studio settings. Blank template values do not disable credentials saved in Studio. The secret stays on the server. Both participant login and signup use the same Google flow: new accounts are created through Sign up, while Sign in requires an existing active account with the exact verified email. Google users enter their own name and can edit only name/phone in their profile. Disabled or conflicting accounts remain unavailable. Staff access is granted only to existing authorised staff accounts.

For local testing, create a separate development client with origin `http://localhost:8000` and redirect `http://localhost:8000/oauth.php`. Do not change the production callback to localhost.

Once credentials are saved, “Continue with Google” appears on both participant forms. Test a new participant and an existing participant in a normal browser. Real consent, code exchange and callback verification require your configured Google project; local simulated tests cannot verify Google's external configuration.

## 6. Email, events and payment review

Configure SMTP in Studio → Integrations using the actual mailbox credentials. Password signup needs email verification; Google supplies a verified email directly. Send a verification message to an address you control before opening registration.

For each event, the assigned coordinator edits:

- Published information, rules, registration opening/closing dates and capacity.
- Existing interest and main registration forms are fixed and shown as read-only summaries. Both Treasure Hunt forms retain team name and issued ID. A new format is applied in code after approval.
- Games under **Games and competitions**. Mobile Legends/MLBB and BGMI are available for Joystick. Add other confirmed games here, save, then assign a custom pass to a game if it needs a separate fee or capacity. Fixed game-specific questions remain in the existing form. A shared pass shares its capacity across the event's games.
- UPI, bank or other receiving instructions, and the recipient name. Use actual accounts only.

Participants choose a game where required, then a compatible pass and payment method. Instructions, selected game and form answers are saved with that registration. Editing a label or receiving account later does not rewrite that saved record. Uploading evidence creates a pending review; no paid ticket is released until a coordinator confirms the exact credit in the receiving account. Tickets can be blocked/unblocked with a recorded reason. Refunds record money already transferred by the organiser; the website does not move money.

Before public launch, use your own real test registration, confirm the actual transfer, review it and check the ticket. If you reverse the payment, record the real refund. Use Registrations & payments and Tickets & check-in to review the records, then export the event registrations and attendance. Finance management is retired from Studio.

## 7. Public content and final checks

The home-page Anazori keepsake uses a visitor-entered name and downloads a video without an account. It is generated in the browser and is not valid for event entry; event registration and admission tickets keep their separate account flow.

Publish actual sponsor names/logos in Studio. The folded blue poster renders only published partners; without them it displays an invitation to partner. Add correct sponsor-contact, venue and social links, confirm festival dates, and review the privacy/terms copy for the organising team's actual practices.

Check a 320–390px phone and a desktop: mobile menu, swipe event selection, Joystick game/pass choices, Google callback, proof upload, ticket access and saved story poster. Confirm `/deploy/`, `/data/`, `/config/`, private screenshots and `.sql` files cannot be requested publicly. The supplied Apache rules block these locations; the local development router also denies them.

Decorative SVG animation loads only near visible scenes and stops offscreen, when hidden, with reduced motion or Save-Data. The story PNG is generated only when requested. Compression and cache rules are provided in `.htaccess`. Hostinger's real response time and capacity still depend on your plan, traffic, database and uploaded media.

## Developer commands

Run `npm ci` and `npm run build` after browser-source changes. Run `php scripts/build-hostinger-sql.php` against the local SQLite content database to regenerate a **clean initial installation**; it is not a live-data backup. Run `python scripts/package-hostinger.py` to rebuild the upload archive. Read `docs/ARCHITECTURE.md` for the code map and access/payment invariants.
