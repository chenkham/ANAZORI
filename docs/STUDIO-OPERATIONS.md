# Organiser Studio

Sign in at `/login.php`. The master account creates staff in **Team access** and assigns each coordinator to the correct event. Participant signup never creates a staff account.

## Event work

Choose an event in **Event workspace**, then use the sidebar. There is one navigation menu.

- **Overview:** registration totals and entry counts for the selected event.
- **Events:** information, dates, registration phase, rules, prices, capacity and receiving payment details.
- **Registrations & payments:** registration answers, screenshots, transaction references, payment approval and completed refund records.
- **Tickets & check-in:** issued tickets, attendance and block/unblock controls.
- **Interest & applications:** existing interest submissions and their review status.

Event coordinators automatically receive these event operation permissions when their staff account is saved. Existing coordinator accounts receive the same permissions through an additive migration. Assignments still determine which events they can access. No assignment means no event records. Only the master can change staff assignments; shared participant account changes require festival-wide access. Permission changes revoke old staff sessions.

## Fixed forms

The existing interest and registration forms are fixed until a new approved format is added in code. Event setup shows a read-only list of each form's fields. Saving dates, prices or event content cannot replace the saved questions, accepted team IDs, headings or submit labels, including through a crafted request.

Treasure Hunt retains its team name and organiser-issued ID fields. Accepted IDs validate on the server and are not disclosed to visitors. Joystick alone has game creation and game-specific pass controls. Fixed game-specific questions continue validating only the selected game's answers.

## Registration, payment and tickets

1. A participant signs in with a verified email and completes the event registration form.
2. The saved registration opens its payment page with the chosen event account. Bank transfers show the bank, account number and IFSC; UPI shows the saved UPI ID and any uploaded QR.
3. The participant submits a payment screenshot, transaction reference/UTR and payment date.
4. The assigned coordinator checks that exact reference and amount in the receiving account, then confirms payment or requests a correction.
5. Confirmed payments issue the entry tickets once, within event capacity. Free competition registrations issue immediately. A screenshot alone does not issue a ticket.

Inauguration is an opening ceremony, with no registration, payment or participant tickets. Its Studio workspace contains programme information.

Cultural Night accepts free performer applications. A signed-in, verified participant supplies a contact number and performance details. In the Cultural Night workspace, **Performers** shows the list and its CSV download. **Confirm & issue ticket** creates one free ticket for that performer; **Decline** creates none. Participants see the application status and confirmed ticket in their dashboard. There are no price, payment, screenshot, pass quantity or audience registration controls for this event. Coordinators can open or close performer applications or schedule their dates.

Payment destinations, registration answers and prices are snapshotted. Later edits cannot rewrite older orders. Screenshots are stored outside the public website and require participant or assigned staff access. Full refunds void tickets; refund records describe money already returned by the organiser and do not send money.

Admission tickets use a simple printable design and one PDF download. Each QR admits one person once. The home-page MP4 keepsake is separate and is not an event ticket.

## Publishing and platform

Publishing manages photos, people, sponsors, collaborations and FAQs. Public files are in `uploads/media/` or bundled `assets/`; their metadata and published content are in the database. These files use local disk in development and the Hostinger hosting account's disk after deployment.

Team and platform controls include staff access, participant accounts, sign-in history, activity, Google/SMTP settings and password changes. Finance, budgets, expenses and closeout management are removed from the active Studio, including direct routes and posted Finance commands. Historical database records are retained for backups.

Google sign-in uses the verified email and requires an existing active account when signing in; explicit signup can create a participant account. Full names are entered by the participant. Profile edits allow name and phone only. Configure real verification mailbox delivery after Hostinger deployment, as requested. See [docs/GOOGLE-SIGNIN.md](docs/GOOGLE-SIGNIN.md) and [docs/HOSTINGER.md](docs/HOSTINGER.md).

The separate venue app uses `/api/checkin.php` with an authenticated staff session, CSRF token and `tickets.scan` permission. Scanner-only accounts can check in their assigned event without participant or payment lists.
