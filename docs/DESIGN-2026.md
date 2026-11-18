# Anazori V16.0 — design and implementation

## Direction

Retro festival posters and analogue sound: warm cream, coral, mint, violet and the existing cyan/pink accents, with local Clash Display typography and real festival footage. Bold navigation sits above a luminous ANAZORI V16.0 wordmark. The headline and actions frame the video. The footer repeats the animated ANAZORI wordmark. V16.0 is the edition; 2026 remains the year. Decorative small section headings are removed; essential form and information labels remain.

The previous homepage was inspected at https://anazori.ccsdu.in; its full capture remains at `.local/reference/previous-live-full.png`. Research included [Lusion](https://lusion.co/), [Active Theory](https://activetheory.net/), and [Awwwards interactive sites](https://www.awwwards.com/websites/web-interactive/?page=5). The implementation and decorative artwork here are original.

## Experience

- Original cropped festival footage with embedded soundtrack in `assets/2026/hero-sound.mp4`. Video remains muted while its soundtrack is played by the global audio controller, with graceful autoplay fallback and a floating sound control.
- A particle field with subtle pointer response, measured text entrances, left-to-right ribbon, and reading progress.
- Animated countdown cells and orbital duration artwork. Unset dates display “Dates dropping soon” until organisers publish a schedule.
- Culture × Tech centres on an original CSS vinyl record, waveform, needle and orbit. An accessible frequency slider changes colour, record speed and the mix caption. Pointer movement tilts the artwork, and motion pauses offscreen or with reduced motion.
- The current admin-controlled introduction video presentation is preserved, including local video and supported external embeds.
- Gradient event frames, memory gallery, custom people groups and a sponsorship bento grid with coral invitation, green waveform, violet ticket and cream contact tiles. Footer social links form one horizontal row.
- A centred organiser studio groups content, operations, connections and team tools; mobile groups are collapsible. See `ADMIN-GUIDE.md`.
- Mobile participant account and dashboard pages hide the footer and sound controls. The website scanner interface is removed; the authenticated check-in API remains for a separate app.

## Motion and delivery

Motion preferences persist and reduced motion is respected. Video pauses offscreen, when hidden, during dialogs and when motion is paused. Ambient audio stays independent of scroll/motion and pauses in hidden tabs. Data-saving visitors receive the poster unless they opt in. The existing introduction-video configuration is retained. Particles are reduced on mobile and pause offscreen. Native scrolling is retained. Runtime assets are local.

Audible autoplay depends on browser policy: [Chrome's explanation](https://developer.chrome.com/blog/autoplay). A user gesture may be required.

## Source map

- Public templates: index/events/event/gallery/teams PHP files and includes/header/footer/festival.
- CMS: includes/cms, cms-schema, cms-actions, cms-fields, cms-seed PHP files.
- Studio: admin/login/logout PHP, src/console.css and console.js.
- Layout: src/site.css, src/flagship.css, src/festival.css and src/portal.css retain shared layouts. src/retro.css and designer.css preserve the vinyl Culture × Tech and colourful sponsor bento; atlas.css and world.css provide the cinematic public theme. public.css bundles these layers into one stylesheet.
- Interaction: src/site.js, motion.js, experience.js, retro.js, designer.js, atlas.js and world.js.
- Submissions: api/interest.php accepts current interest and registration modes. Older endpoints return retirement messages.

## Build and validation

`npm run build` compiles public/studio and checkout assets. `npm run serve` starts http://127.0.0.1:8088 with upload limits configured.

- `npm test`: pages, assets, routes, private-file protection, interest validation/storage, PHP syntax.
- `npm run test:browser`: five public routes at 360/390/768/1024/1440 px, motion/audio, Three.js, mobile navigation, filters, submissions, gallery keyboard use, fallback modes, automated WCAG A/AA checks.
- `npm run test:cms`: migration, passwords, dates, uploads, CRUD, registration phases/schedules, stale/duplicate forms, legacy endpoints, permissions, revoked sessions, audit log, studio accessibility and layout.
- `npm run test:retro`: wordmarks, keyboard frequency mixing, mobile account/dashboard focus, studio grouping, scanner route removal, five responsive widths and reduced-motion behaviour. Screenshots live under .local/retro.
- `npm run test:scroll`: real forward/reverse scrolling, hero and atlas progress, keyboard focus, category switching, five responsive widths, pause/resume, reduced motion, Save-Data, no JavaScript and persisted-page lifecycle simulation. Screenshots live under .local/scroll.
- `npm run test:participants`: participant authentication, payment verification, pass downloads, QR decoding, check-in API permissions, refunds, password reset and Google OAuth state/PKCE.
- `node scripts/flagship-qa.mjs`: screenshots/diagnostics under .local/flagship.

Tests use disposable databases, and CMS tests isolate uploads. The preview retains zero dates and original event preview states. Real-device performance, Core Web Vitals, and production MySQL have not been measured.

## Recovery

Pre-CMS files: `.local/backups/cms-2026/`. Previous design backups: `.local/backups/flagship-2026/`. Participant history is retained. No production deployment has been performed.

## Festival frames and navigation

The final public layers include `src/designer.css`, `src/cards.css`, `src/atlas.css` and `src/world.css`, loaded after `retro.css`. They coordinate transparent engraved navigation, cinematic event cards, photo and portrait frames, sponsor bento tiles, filters, forms and dialogs. Navigation stays at the beginning of the document and scrolls away with the page. Its text labels have no icons. The compact menu activates at 960px and supports Escape and keyboard focus. Event and ticket print styles preserve readable paper output.

Research: [KIKK Festival 2018](https://dogstudio.co/cases/kikk-festival-2018/) for fine rules, grids and consistent transitions; [KIKK Festival 2016](https://dogstudio.co/cases/kikk-festival-2016/) for iridescent retro accents; [Tomorrowland](https://dogstudio.co/cases/tomorrowland/) for a game-like festival atmosphere. The Anazori implementation is an original interpretation. These sources are design references, not endorsements of this website.

`npm run test:retro` now also checks the stationary bar, visible keyboard focus around ticket cards, landscape menu scrolling and the tablet-to-desktop transition. Updated screenshots live under `.local/retro`. Pre-frame source copies are in `.local/designer-before`.

## Participant platform

Email/password and Google OAuth accounts, SMTP verification/reset codes, PhonePe order/payment verification and signed webhooks, digital QR/PDF passes, capacity reservations, refunds, venue scanning and granular staff permissions are implemented. Provider credentials are entered by the master Super Admin in Integrations. See ADMIN-GUIDE.md for setup, testing and hosting requirements. No live credentials or real test charges are included.

Validation completed: 6 public integration groups, 7 public browser groups, 7 CMS groups and 7 participant/payment/ticket groups. The rendered single-page PDF was also decoded successfully as a real QR pass. npm and Composer audits reported no advisories. Tests use disposable SQLite data, a local gateway fixture and private email outbox. Live provider connectivity, MySQL hosting and physical device-camera testing remain external setup checks.

## Cinematic event explorer — revision 2026.21

The homepage uses an original gateway panorama and a lightweight SVG constellation to browse the real CMS programme. The heading is “Find your event. Get your ticket.” Circular map selectors display live category event counts and are the only category controls. Extra CMS categories get matching circles below the map. Map labels and event cards use words without glyphs or arrows. Cards lead to existing event pages; the current registration phase, capacity and payment flow remain authoritative.

Culture × Tech retains the preceding vinyl record, waveform, frequency control, typography and gradient. The full sponsor section retains its preceding cream background and coral, green, lavender and cream bento design. Their colours are scoped locally so the surrounding cinematic theme cannot replace them. The experimental 3D gate is no longer mounted or imported by the public entry point.

Public CSS is bundled into one request; audio waits for activation, and map animations respect reduced motion, data saving, visibility and the global motion control. The artwork is a 235KB WebP. See FESTIVAL-DEPLOYMENT.md for hosting and traffic validation; production capacity has not been measured.

Artwork: `assets/2026/anazori-world.webp`, original source preserved in `.local/world-before/anazori-world-source.png`. It was generated with the imagegen skill and re-encoded to WebP for delivery. Prompt brief: panoramic futuristic techno-cultural festival gateway above dark reflective water, interwoven warm coral Assamese textile forms and icy cyan technological ribbons, luminous violet architectural accents, a dark left area for interface controls, cinematic atmosphere, no text, logos, watermark or characters.

## Scroll choreography — revision 2026.23

`src/scroll-motion.js` seeks paused browser animations from native scroll progress. The hero video and title move at different depths; the constellation assembles with orbit rotation and a light sweep; event rows enter in sequence; the vinyl arrives with a gentle turn; memory photography shifts within its frame; sponsor tiles arrive as a bento sequence; the footer wordmark settles into place. Gallery, catalogue and people cards receive restrained entrances. The nav stays anchored to the document, and account, checkout and Studio screens have no added scroll effects.

Individual translate/scale/rotate properties preserve existing vinyl tilt, record spinning, atlas positioning and hover effects. Geometry uses natural layout offsets and is refreshed after resize, fonts, images and changing event categories. One passive scroll handler schedules a frame only when needed; offscreen scenes are skipped. The approach follows [WAAPI seeking](https://developer.mozilla.org/en-US/docs/Web/API/Animation/currentTime) and [transform/opacity animation guidance](https://web.dev/articles/animations-guide).

Motion distances are reduced on phones. Reduced motion, the existing Pause motion control and Save-Data cancel the effects and restore the ordinary layout. Keyboard focus reveals a control immediately. Unsupported animation properties and disabled JavaScript leave content readable. Scrolling stays native, with no pinned sections or forced snapping. Ordinary-device frame rates and production traffic capacity have not been measured.

## Readability and circle navigation — revision 2026.24

Culture text containers allow italic letter overhang and mobile type is sized to fit the two-column layout. The vinyl grooves and sheen rotate independently of the central ANAZORI V16.0 label, which is larger, upright and layered above the waveform. The slider and existing colour mixing remain intact.

The duplicate rectangular category controls are removed. Each circular node shows its live published-event count, with the category below and an accessible label. Tapping or activating a circle with Enter/Space switches the event list and centre caption. Additional CMS categories use the same circle design below the constellation. With JavaScript disabled, all category event links remain visible.

## Mobile performance — revision 2026.27

The current scroll engine uses native root scroll timelines and additive transform keyframes where supported, with the earlier cached frame-seeking path retained for older browsers. Visible artwork and choreography are preserved. Text remains opaque during entrances, offscreen effects sleep, and separated entry/exit observer margins avoid boundary activation loops. Printing cancels choreography and screen view restores it. `PERFORMANCE-2026.md` records the changes, repeatable benchmark, validation and physical-device limits.

## Hero glow and sponsor preview — revision 2026.28

The hero name has two cached cyan/violet neon halos with a slow breathing opacity/scale animation. The gradient lettering remains crisp. The glow follows the existing offscreen, motion-pause and reduced-motion controls; its generated text has empty accessibility alternatives so the heading is announced once.

Sign in is visible beside the menu on phones, with a 44px minimum tap target. The signed-in label remains My festival. The header edition badge is hidden on small screens to make room; V16.0 remains in the main hero. The mobile menu uses the correct account link and label for the current session.

When no sponsors are published, two sample cards show SBI and Red Bull above the existing sponsorship bento. Both cards and the nearby note explicitly identify them as design previews, with no confirmed partnership implied. Publishing real sponsors in the Studio replaces these cards automatically. No sponsor database records were added. The SBI image is a local copy of the [official website logo](https://home.sbi.bank.in/o/SBI-Theme/images/custom/logo.png); the Red Bull preview uses a typographic wordmark and brand-colour accent. No remote requests are needed to render these cards.

Visual review passed at 320, 360, 390, 560, 768, 1011, 1234 and 1440px, including mobile login navigation, glow motion, reduced motion and readable preview status. Screenshots are stored in `.local/polish`.
