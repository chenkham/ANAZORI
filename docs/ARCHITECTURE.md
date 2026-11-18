# Architecture and handover

## Modules

| Location | Responsibility |
| --- | --- |
| Root PHP pages | Public pages, account screens, participant dashboard and studio entry points |
| `api/checkout.php`, `api/payment-proof.php` | CSRF-protected registration and screenshot submission |
| `includes/cms.php`, `cms-schema.php`, `cms-actions.php` | Content storage, validated editors, publishing and revision checks |
| `includes/platform.php` | Participant sessions, email verification, Google/SMTP configuration and rate limits |
| `includes/registration-forms.php` | Stable form field IDs, field validation and participant answers |
| `includes/game-categories.php` | Stable game IDs, active choices and game/pass compatibility |
| `includes/google-auth.php`, `oauth.php` | Verified Google identity linking, state/PKCE and server token exchange |
| `includes/manual-payments.php` | Payment methods, private proofs, review, reservation locking and ticket controls |
| `includes/certificates.php`, `certificate.php`, `certificate-verify.php` | Event podium results, account-linked certificate PDFs, and public QR verification |
| `includes/payment-view.php`, `event-setup-view.php` | Receiving-account display, review controls, event setup and read-only form summaries |
| `includes/studio-coordinator-workflow.php` | Saved coordinator grants, one-time migration and fixed-form preservation |
| `includes/commerce.php` | Prices, capacity, orders, ticket issuing and check-in; historical gateway reconciliation |
| `includes/studio-access.php` | Current staff grants, event assignment checks and event activity |
| `includes/studio-workspace.php`, `studio-operations-view.php` | Scoped participant/payment/ticket lists and exports |
| `includes/studio-finance.php`, `manual-finance.php` | Retained historical journals and registration refund/accounting helpers; Finance management routes are retired |
| `src/` | Editable CSS and JavaScript; `scripts/build.mjs` generates public bundles |
| `includes/festival-scenes.php`, `src/festival-scenes.js` | Character placement, mobile event swipes and visibility-controlled SVG motion |
| `includes/intro-video.php`, `intro-video-view.php`, `src/intro-video.js` | CMS-controlled introduction film, original cinema frame and visibility-controlled muted autoplay |
| `src/reference-background.css`, `includes/release-updates.php` | Exact supplied page gradient and one-time transfer of the former hero video into the film panel |
| `tests/` | Isolated service invariants and browser journeys |
| `includes/sponsor-stage.php`, `share-station.php`, `src/festival-sharing.js` | Published partner poster and on-demand story-image sharing |
| `config/runtime.php`, `deploy/`, `docs/HOSTINGER.md` | Private production settings, clean initial SQL and upload package |

The current localhost installation uses MariaDB (visible in local phpMyAdmin). SQLite remains available for isolated tests and as the preserved migration backup. Production uses the configured Hostinger MySQL/MariaDB database. Schema installation adds tables without replacing existing orders. Money uses integer paise. All date comparisons for participant payment dates use India Standard Time; audit timestamps use UTC.

## Managed content and media

Studio saves site settings in `cms_settings` and event, gallery, people, sponsor, collaboration and FAQ content in `cms_content`. Public PHP pages read published records from this database. A published save changes what visitors see on their next request; a draft remains unpublished. Fixed interface labels and page layout still live in PHP/CSS/JavaScript.

Actual public uploads live in `uploads/media/` on the website filesystem; `cms_media` holds the filename/path, MIME type, size and other metadata. Bundled artwork and photos live in `assets/`. These are local disk files during development and Hostinger account disk storage after upload/deployment; no external object-storage service is connected. Participant MP4 keepsakes are generated/downloaded in the visitor's browser and are not saved to the server. Back up media files together with the database.

## Fixed event forms

The existing interest and main registration forms are fixed. Studio renders a read-only summary, and every event save preserves their schemas, stable field IDs, headings, descriptions and submit labels. Crafted question posts cannot change them. A new approved format can be applied in code when supplied.

Joystick alone has game creation and game-specific pass controls. Existing game-specific questions still validate only the selected game's answers. Treasure Hunt keeps team name and issued ID fields. Accepted-ID lists remain server-only, and leading zeros are preserved.

## Registration and ticket states

```text
Paid pass → AWAITING_PROOF → PENDING_REVIEW → PAID → tickets issued
                               ↓ correction
                            REJECTED → new proof → PENDING_REVIEW

Expired reservation + confirmed money + no capacity → PAID_REVIEW
Increase capacity and approve again, or return the payment and record the refund.

Free pass → PAID → tickets issued immediately
Ticket: VALID → USED (single entry)
        VALID / USED → BLOCKED → previous VALID / USED
Full refund: order REFUNDED, all tickets VOID
```

`az_orders` holds the immutable registration snapshot and answers. `az_manual_payments` holds the chosen receiving-account snapshot, current proof, review revision and confirmed amount. `az_payment_proofs` retains every uploaded version. `az_payment_reviews` retains review/refund actions. Account changes and form edits affect future registrations, not existing ones.

## Certificates and results

`az_certificate_awards` maps event teams to podium places. `az_certificates` stores the issued name/team, participant account, source registration, certificate ID, encrypted verification token and current issue status. The participant account controls access to the PDF. Public QR verification uses a token hash and displays only the recipient, team, award/status, event, issue date and certificate ID. Email and phone remain private. Event coordinators manage results and certificates within their existing event assignment and ticket-control permission.

Approval requires `payments.verify`, an assigned event, a current session, the current review revision, and an explicit confirmation of the exact received amount. Ticket issuance and capacity checks run in the same locked transaction. Approval replays cannot create additional tickets. A normalized transaction reference cannot be claimed by two pending or approved registrations against the same receiving account. Rejection frees an unconfirmed reference while preserving all evidence and review history.

## Access and private files

Permission labels are separate from roles. Event assignments deny access by default. Only the fixed Super Admin identity is automatically global. Staff may receive explicit festival-wide access. A coordinator cannot assign their own events or disable a participant's shared account.

Mutations reread staff account grants after acquiring the database lock. Proof downloads reread current participant/staff access and use the parent order's event. Unknown or forbidden evidence returns 404. Files are served with private/no-store caching, fixed image MIME types and no-sniff headers. Uploaded screenshots must be real JPG, PNG or WebP images up to 5 MB; SVG and executable uploads are rejected. SHA-256 checks detect changed evidence.

Set `ANAZORI_PAYMENT_PROOF_DIR` and `ANAZORI_STUDIO_RECEIPT_PATH` to **absolute paths outside the public website**. Defaults use a sibling `anazori-private` directory. PHP must have write access to these paths. The studio rejects private storage inside the public root. Keep any older expense receipts when changing their storage path: move them together and retain their stored filenames.

The upload and authorization design follows the [OWASP upload guidance](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) and [authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## Retained historical accounting

Finance, budget, expense and closeout management are removed from the active Studio. Direct routes and posted Finance commands are denied. Historical tables remain intact for existing records and backups. Payment review, completed refunds and ticket controls continue under assigned event permissions in Registrations & payments.

## Deployment

1. Install Composer dependencies; build assets with `npm ci && npm run build`.
2. Set production application mode, public URL, database credentials, bootstrap password for a fresh installation, and private storage paths. SQLite checks and the clean-import/application checks on MariaDB 11.4.10 pass. See [Hostinger setup](HOSTINGER.md) for the exact anazori.ccsdu.in callback, private config and database import.
3. Upload compiled assets, PHP application code and Composer dependencies. Keep `.local`, tests, source downloads, `.env`, databases and private evidence out of public hosting. Apache `.htaccess` blocks sensitive directories; the development router provides equivalent protection.
4. Configure mail and Google in Studio → Integrations. Set the Google callback to the exact public origin plus `/oauth.php`.
5. Assign coordinators, publish each event's actual methods and registration form, and verify a full registration/review/ticket journey before advertising paid registration.
6. Back up database, private screenshot/receipt directories and the persistent application encryption key together. Restore filenames and permissions exactly.

New registrations use one website workflow and require no gateway credentials or test/live selector. The old provider modules and records remain for historical refunds and reconciliation. Do not delete them while historical orders still depend on them.

## Character motion

Public characters use supplied SVG performances and existing transparent artwork. SVGs have visible static fallbacks; selected visible scenes load motion. Totoro and the gallery companion loop while visible. Brief entrance scenes can replay after leaving and re-entering the viewport. Offscreen scenes, hidden tabs, reduced motion, Save-Data and the site's motion switch use stills. There is no 3D world or rendering engine. New participant/studio screens contain no character performances.
