# Organiser Studio

Sign in at `/login.php`. The master account creates staff in **Team access** and assigns each coordinator to the correct event. Participant signup never creates a staff account.

## Event work

Choose an event in **Event workspace**, then use the sidebar. Event tabs also link directly to Forms, Payment review and Participant details.

- **Overview:** registration totals and entry counts for the selected event.
- **Events:** information, dates, registration phase, rules, one entry fee, individual/team ticket, capacity and expandable Form setup. Opening the form editor saves the event details first.
- **Forms:** registration/interest editors, or the contribution editor for Inauguration and Cultural Night.
- **Payment review:** registration answers, screenshots, transaction references, payment approval and completed refund records.
- **Participant details:** response spreadsheet, every submitted answer and PDF, Excel (.xlsx) and CSV exports for event preparation.
- **Tickets & check-in:** issued tickets, attendance and block/unblock controls.
- **Results & certificates:** edit event podium teams, issue achievement or participation certificates to confirmed registration accounts, add teammate certificates, and revoke or restore issued certificates. Participants download their certificates from My festival. Each QR opens a public Anazori page showing the recipient, team, result and certificate ID; email and phone are never shown there.
- **Interest & applications:** collected interest only, without confirmation or approval actions. Inauguration and Cultural Night show Contributions here instead.

Event coordinators automatically receive these event operation permissions when their staff account is saved. Existing coordinator accounts receive the same permissions through an additive migration. Assignments still determine which events they can access. No assignment means no event records. Only the master can change staff assignments; shared participant account changes require festival-wide access. Permission changes revoke old staff sessions.

## Form setup

Open an event, expand **Form setup**, then choose its registration or interest form. The dedicated editor uses familiar Questions, Responses and Settings tabs. Event details, passes and capacity stay on the event setup page.

- Add short answers, paragraphs, multiple choice, checkboxes, dropdowns, uploads, scales, ratings, grids, dates, times and consent questions. Sections create participant pages; text, image and video blocks add instructions.
- Use the side toolbar to insert items, import a downloaded JSON form template, or add payment QR and screenshot questions. Upload QR images directly or choose existing media. Set the screenshot's upload purpose to **Payment screenshot**.
- Use each question's **More question settings** for descriptions, validation, conditions, private accepted IDs and answer keys. Required grids require an answer in every row. Conditions use an earlier answer; a section condition applies to the whole section.
- Drag the handle or use the up/down arrows to reorder. Duplicate, undo/redo and preview are available. Question identities remain stable when labels or positions change.
- Changes autosave as a **draft**. **Publish** validates and applies the form. A general event save preserves its questions and draft. Concurrent edits require reloading; download the question template first if needed.
- Settings control accepting responses, edits before approval, section progress, question shuffling, automatic quiz scoring and the confirmation message. Each account always has one registration per event. Conditional forms keep question order. Interest and contribution forms collect responses without tickets or quiz scoring.

Treasure Hunt retains its organiser-issued ID validation, with accepted values checked privately on the server. Joystick alone has game creation and questions/pass controls for specific games. Existing registrations keep their original schema, answers and prices when a coordinator later publishes changes.

## Registration, payment and tickets

1. A participant signs in with a verified email, completes the form. The server assigns one individual ticket or one shared team ticket according to the event setup; participants cannot choose quantities or ticket types.
2. The coordinator's image/text blocks provide payment instructions. Participants upload screenshots, identity proof or other requested files in the same form. Add the receiving UPI ID to an image/QR question to offer Pay with UPI, or let participants save the QR image. Progress is saved before opening a payment app.
3. The response appears under **Responses** and **Registrations & payments**. No ticket is issued yet, including for free registrations.
4. The assigned coordinator opens the private files and checks paid entries against the actual receiving account. The verified amount must match the pass price. Duplicate transaction references cannot approve separate form registrations.
5. **Approve & issue ticket** issues one ticket once, subject to capacity. **Request correction** returns a note and lets the participant edit their original response. **Decline application** closes it without a ticket. Approved responses are locked.

Files are stored outside the public directory, in `../anazori-private/registration-files/` by default, or `ANAZORI_REGISTRATION_FILE_DIR`. The database stores ownership and file metadata. Downloads require the participant owner or permitted staff assigned to the event. Interest uploads are accessible to the assigned review team. Files are limited to 20 MB each, 20 files and 60 MB per response; PHP's configured upload limits can impose a lower cap. Back up the private directory together with the SQL database.

Text answers autosave to the participant account, with a device copy for interrupted connections. Completed uploads are saved privately before submission. Participants can resume from My festival > Continue registration after signing in again. Wait for Saved to your account before leaving; unfinished uploads cannot be restored. Stale tabs cannot overwrite newer account drafts.

Responses can be viewed as individual applications or a spreadsheet and exported as PDF, Excel or CSV, including every form answer and authorised attachment links. Old registrations retain their original payment review flow and proof history. Full refunds void tickets; recording a refund describes money already returned and does not transfer money.

Admission tickets use a simple printable design and PDF download. Each QR is checked in once: an individual ticket admits its participant, and a team ticket covers its registered team. The home-page MP4 keepsake is separate from the event ticket.

Inauguration and Cultural Night show Preview and Contribute. Coordinators build their contribution forms in Form setup; received contributions never issue tickets.

## Publishing and platform

Publishing manages photos, people, sponsors, collaborations and FAQs. Media fields accept direct uploads and select the result immediately; it also becomes available in Media library and Gallery photo choices. Uploading a QR or logo does not publish it as a gallery post. Save the content page to publish the selected file. Explore events uses the homepage character art when no event cover is selected.

Public files are in `uploads/media/` or bundled `assets/`; their metadata and published content are in the database. These files use local disk in development and the Hostinger hosting account's disk after deployment.

Team and platform controls include staff access, participant accounts, sign-in history, activity and password changes. Integrations is removed from the active menu. Website settings contains editable Privacy policy and Terms text (use ## for headings). The footer links to these pages and credits Blitz. Finance, budgets, expenses and closeout management are removed from the active Studio, including direct routes and posted Finance commands. Historical database records are retained for backups.

Google sign-in uses the verified email and requires an existing active account when signing in; explicit signup can create a participant account. Full names are entered by the participant. Profile edits allow name and phone only. Configure real verification mailbox delivery after Hostinger deployment, as requested. See [docs/GOOGLE-SIGNIN.md](docs/GOOGLE-SIGNIN.md) and [docs/HOSTINGER.md](docs/HOSTINGER.md).

The separate venue app uses `/api/checkin.php` with an authenticated staff session, CSRF token and `tickets.scan` permission. Scanner-only accounts can check in their assigned event without participant or payment lists.
