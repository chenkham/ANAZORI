# Organiser and public-site update

## Result

- Sponsors use the supplied blue locker/folded paper direction. Only published CMS partners are rendered; no sample brands are presented as sponsors.
- Stitch replaces the equalizer in the sponsor invitation. A visitor can choose an event and save/share a 1080×1920 story PNG generated in the browser. A static SVG download works without JavaScript.
- Mobile navigation uses an angled frame and a short light trace. The studio sidebar is white, with line separators and rotating chevrons in expandable groups. Repeated diagonal action arrows were replaced with context-specific symbols.
- Joystick shows only Mobile Legends artwork. Editable game choices have stable IDs, game-specific or shared passes, required server-side selection, frozen registration/ticket labels, scanner labels and game-filtered payment/ticket exports.
- Treasure Hunt replaces Futsal while preserving the event ID and historical registration snapshots. A cartoon T-Rex replaces the fireball chase. The new source is credited publicly.
- A clean MariaDB SQL installation and a 47.7 MB PHP upload archive are prepared for anazori.ccsdu.in. Credentials live in a private file outside the document root. Google login/signup use the server OAuth flow with state and PKCE; real client credentials still need to be supplied.

## Verification

The checks use isolated test databases, local servers and generated fixtures. They do not create records in the real participant database or make payments.

- Clean SQL import and application migrations passed on MariaDB 11.4.10.
- Manual payment: 39 service checks and 9 browser groups, including private screenshot upload, correction, bank-confirmed approval, block/unblock, exports, refunds and no-JavaScript registration.
- Access control: 32 event scope checks. Finance: 91 journal, budget, approval and reconciliation checks.
- Game selection and Google identity linking: 21 checks. Live Google consent/token exchange needs the actual Google project.
- New release: 6 browser groups covering sponsor records, story export, mobile menu, Google redirects/invalid state, game checkout/editor/filtering and private path denial.
- Character scenes: 7 browser groups; supplied animations: 4 groups; content mapping: 4 groups. Public layout checks cover 320, 390, 768 and 1440px; participant/studio checks also cover 599 and 1011px.
- Automated WCAG checks pass for the tested pages and new sponsor/sharing section. These are automated checks, not a complete manual accessibility audit.
- A 390×844, 6× CPU-throttled local Chromium scroll run had no runtime errors, median frame interval 16.7ms and 95th percentile 50ms. This is a stress-test result, not a promise of constant 60fps on every phone. Scenes use static fallbacks, visibility guards and reduced-motion/Save-Data handling.

Follow [HOSTINGER.md](HOSTINGER.md) for database creation, private configuration, Google credentials, SMTP and launch checks. Hostinger's live network, SSL and account credentials have not been exercised from this local workspace.
