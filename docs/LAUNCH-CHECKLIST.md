# Anazori launch handover

## What is configured on this computer

- Website: <http://localhost:8000/>. Organiser Studio: <http://localhost:8000/login.php>.
- MariaDB stores the actual retained local records. phpMyAdmin: <http://localhost:8001/>.
- The database username/password are in `the private local database access file`, outside the website. The original `data/anazori.sqlite` is retained as a migration backup; new local activity writes to MariaDB.
- The supplied Google client ID and secret are in `the private local configuration file`. You confirmed a real local Google sign-in. Production still needs the exact deployed callback registered in its Google Console client.
- You confirmed that Continue with Google works locally. First-time Google participants now enter their own full name; Google names are not imported. My festival → Edit profile allows only name and optional phone edits. These values are stored in the shared participant database.
- Home keepsake: visitor-entered name, no account, MP4 download only. It is a keepsake, not an admission ticket. A browser without MP4 recording support displays a clear message.
- Sponsors retain their blue poster presentation. Collaborations have a separate publishing module and home section, with no invented partners.
- The public website uses a deep violet background matching the supplied V16.0 brochure, replacing the earlier coming-soon gradient at the organiser's request. The former hero film has moved into the restored 16:9 panel with its decorative corner border. Set its video, poster, external URL, player controls, loop and muted autoplay in Website settings → Our spirit & festival film. Existing empty film settings migrate once on startup; clearing the film later in Studio keeps it empty and displays “Official film coming soon”. Entry sound has its own settings group.
- Satoshi is self-hosted in `assets/fonts/satoshi/` for the public pages, Studio and keepsake renderer. The original Fontshare files and their license are included.
- The public theme uses the brochure's actual colours: neon violet `#a24bff`, magenta `#ff3fc8`, cyan `#6fd3ff`, pink-white headings `#ffc8f5`, cobalt borders `#3a55c8`, and deep violet panels `#140a2e`. The homepage Anazori V16.0 artwork has a layered glow with a slow opacity pulse that respects motion controls. Satoshi, layouts, photos and status meanings remain intact. The entire sponsor section retains its preceding design and inherited palette, including the blue poster, collaborations and MP4 keepsake.
- Only the hero motto uses handwritten Bilbo lettering, chosen as a visual match for the V16.0 signature in the supplied logo, with a silver SVG bevel and inner glow based on the supplied Photoshop values. This is a visual match, not a confirmed identification of the original typeface. Both lines remain editable through the existing hero text fields. The locally hosted webfont and OFL license are included.
- The supplied ANAZORI main artwork is preserved exactly and displayed in the main brand positions, including the home hero and MP4 keepsake. Our People uses the supplied festival film border.
- The keepsake uses Satoshi text and a violet, lilac and pearl palette matching the supplied page background. Its lower name section follows the original ticket outline and curved edition wing, with a soft glowing front wordmark. Preview and MP4 export use the same canvas renderer.

Windows Smart App Control blocked the native PHP extension libraries on this computer. The local site uses the installed PHP and MariaDB in WSL Ubuntu. No Windows security settings were disabled. To start again after restarting the computer, run `npm run serve` from this project. Run `npm run phpmyadmin` in a second terminal. If MariaDB is not active, run `wsl -d Ubuntu -u root -- systemctl start mariadb`. Both servers bind to the local loopback address.

Use your existing organiser password or Google after its Console setup. This update preserves existing account passwords. Production receives its own generated bootstrap password in the prepared private file below.

## Actions requiring your hosting and Google accounts

1. **Google Console:** open the project containing your supplied Web application client. Add `http://localhost:8000/oauth.php` to its authorised redirects, with origin `http://localhost:8000`. Follow [GOOGLE-SIGNIN.md](GOOGLE-SIGNIN.md) to test a real sign-in. For public launch, create/configure a separate production project/client, with redirect `https://anazori.ccsdu.in/oauth.php` and origin `https://anazori.ccsdu.in`. Complete the audience and branding steps there. Replace the production private file's Google values with that production client before deployment. The server chooses the correct callback for its current local or deployed origin.
2. **Hosting:** create a new empty MySQL/MariaDB database and database user. Record the full database name, user and password from your hosting panel.
3. **Verification mailbox, after deployment to Hostinger:** enter real SMTP host, port, encryption, username, password and sender in the deployed Studio → Integrations. Hostinger's default is `smtp.hostinger.com`, SSL 465. Other providers can use their own settings. Email/password signup is unavailable until delivery is configured; existing password accounts can still sign in, and Google uses Google's verified email. Local verification delivery is deferred as requested.
4. **Domain:** point `anazori.ccsdu.in` at your hosting, enable HTTPS, and set PHP 8.2 or newer with the extensions listed in [HOSTINGER.md](HOSTINGER.md). Keep `.htaccess` and `.user.ini`. Set `max_input_vars` to at least 3000 in the hosting PHP settings if `.user.ini` is not applied.

You tested Google consent locally. Live hosting, SMTP delivery, production Google callback, DNS and SSL still require your external accounts and a test after deployment.

## Upload these prepared files

| File | Destination / use |
| --- | --- |
| `deploy/anazori-public-html.zip` | Extract into the domain's `public_html`; includes compiled assets and PHP dependencies. |
| `deploy/anazori-hostinger.sql` | Import once into the new empty database using hosting phpMyAdmin. Never overwrite a running festival database with this clean installation file. |
| `the private production configuration file` | Fill the three hosting database placeholders. Upload **above** `public_html` and rename to `anazori-config.php`. Contains the supplied Google credentials and a generated bootstrap password; keep private. Use production Google client credentials for the deployed environment. |

The upload archive and installation SQL contain no local login records, passwords, OTPs, private screenshots, database files or Google secret. The SQL includes saved public website content and empty operational tables. First production Studio login uses `chenkhamchowlu@gmail.com` and `ANAZORI_BOOTSTRAP_PASSWORD` from the private production file; change it when prompted. PHP creates the private application key and evidence directories. Back up that key, private evidence and the database together.

## Account access and profile

Sign in requires an existing active database account. An unknown Google email is rejected without creating an account; choose Sign up to register it first. The stored account ID, exact email, active status and session version are checked on every authenticated request. Deleted, disabled, mismatched or stale accounts cannot enter the dashboard. Google signup asks for a manually entered full name before dashboard access. Users can edit only their name and optional phone through My festival → Edit profile. Email and permissions cannot be changed from that form.

## Customise each event in Studio

Open **Events → Edit**. These controls are independent for every event:

- **Registration dates and instructions:** choose Interest, Open, Closed, Completed, or Automatic dates, and edit the closed message.
- **Fixed forms:** interest and registration keep their existing fields and presentation. Event setup shows read-only summaries. New formats are applied in code after approval; coordinators cannot create or alter forms.
- **Treasure Hunt:** team name and organiser-issued ID remain in the saved forms. Allowed IDs are checked on the server, keep leading zeros and are never published as a list.
- **Joystick only:** manage MLBB/BGMI and other confirmed games under Games and competitions. Saved game-specific questions continue working; assign a pass to a game when it needs a separate fee or capacity. Other events do not expose game controls.
- **Payment methods:** enter actual UPI, bank or other receiving details. Bank transfer requires bank, account number and IFSC. Participants save registration, see those details and submit a screenshot with transaction reference and payment date.
- **Passes, prices and capacity:** paid entry requires coordinator verification of the exact received credit before ticket release. Free registrations issue immediately.

Existing registrations retain their question, answer, game and payment snapshots. Studio saves preserve fixed forms and reject truncated event posts. Coordinators receive registration/payment/ticket permissions when created or updated, with records limited to assigned events. Finance, budgets, expenses and closeout management are removed from Studio; historical records remain in the database.

Publish real collaborators in **Publishing → Collaborations & partnerships**: name, type, logo, description, website and sort order. Only published entries appear below sponsors. The heading and section visibility are editable in Website settings.

## Where text and photos live

Studio-managed text, settings, events, forms, gallery captions, sponsors and collaborations are database records (`cms_settings`, `cms_content`). Published PHP pages read them on each request. Drafts remain unpublished; fixed interface labels and layout are still in the application code.

Each homepage event uses its **Event photo / cover** in a tilted photograph frame, with the event artwork at the lower right. Upload your original photograph in **Publishing → Media**, then choose it in **Events → Edit → Event details → Event photo / cover** and save the published event. This same cover is used on its event page. Events without a selected image retain a quiet empty frame.

The supplied **ANAZORI_V16_Brochure_Neon.pdf** sets the initial V16.0 public programme, descriptions, formats, judging criteria, committee and contacts. Prativa was replaced by Youth Parliament on the organiser's explicit instruction. Its existing CMS/legacy event IDs are preserved, old public links redirect, and historical registration/payment/ticket snapshots keep their original values. The brochure update applies once to SQLite or MySQL and preserves subsequent Studio edits. Dates, fees, capacities, bank details and guest-artist identity were not specified in the brochure and are not invented by the update. Existing settings for those fields remain authoritative.

Edit the downloadable brochure in **Website settings → Experiences & culture → Festival brochure PDF**, and contact names, emails and phone numbers in **Website settings → Visit & contact**. Current committee members appear in Our people; previous-edition records absent from the brochure are archived in Studio, not deleted. Bundled committee portraits remain in `coordinators/` and are included in the deployment ZIP.

Uploaded public photos/videos are real files in `public_html/uploads/media/`; file metadata and paths are recorded in `cms_media`. Bundled artwork lives in `assets/`. On this computer these are local files. After deployment they use your Hostinger account's disk storage; no separate storage bucket is configured. Private payment proofs and receipts live outside `public_html`. Browser-generated MP4 keepsakes are downloaded directly and are not stored on the server. Back up both database and uploaded files.

## Inspect accounts and activity

Studio → **Participants** includes accounts that have not registered for an event. Studio → **Sign-in history** records Google signup/login, password signup/login, failed sign-ins, verification sends/results, resets and logout from this update onward. Event-scoped staff cannot read global sign-in history; grant festival-wide participant-view access only when intended.

In phpMyAdmin, select the local `anazori_local` database, or your production database after deployment:

```sql
SELECT id, name, phone, email, email_verified, profile_completed, active, created_at
FROM az_participants ORDER BY id DESC;

SELECT user_kind, user_id, user_name, email, event, method, success, occurred_at
FROM az_auth_events ORDER BY id DESC;

SELECT id, event_id, name, email, status, form_data
FROM submissions ORDER BY id DESC;

SELECT public_id, participant_id, event_slug, state, amount, snapshot, answers
FROM az_orders ORDER BY id DESC;
```

`az_participants.google_sub` links a Google identity. `email_verified` records verification status. `az_challenges` contains hashed one-time codes and expiry/consumption status, not readable OTP values. Passwords are hashed; Google tokens are not stored in the sign-in history. Do not edit authentication flags or order states manually in phpMyAdmin; use Studio actions to retain the related records and audit history.

## Before opening public registration

Open Studio → Integrations → **Launch checks** on the deployed server. Complete a real Google login, a password signup with received email code, an event interest submission, and a main registration. For paid registration, confirm an actual credited payment before releasing the ticket. Check the received ticket, participant dashboard, staff assignments and exports. Test guest MP4 download on your phone and desktop.

The automated checks cover SQLite and MariaDB form validation, custom form persistence, game scope, closed phases, authentication history, one-time email verification, access isolation, coordinator payment/ticket workflows and clean production import. Google Console configuration and real mail delivery still need your end-to-end tests. Browser automation in this session was denied by browser access policy, so this update was checked with server/HTTP tests rather than a fresh visual browser inspection.
