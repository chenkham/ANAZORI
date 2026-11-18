ANAZORI V16.0 — A festival where worlds meet

Creative and implementation blueprint · 4 October 2026

Status: the approved lightweight 2D adaptation is implemented. See `2D-FESTIVAL-IMPLEMENTATION.md` for the delivered features and validation. The detailed cast choreography below remains the creative reference; the implementation uses flat source artwork, SVG scenery and brief interactions, with no 3D world or renderer.

**1. The central idea**

Anazori is the host of a festival that has temporarily brought several fictional worlds together. Characters are visitors, technicians, performers and guides. The festival's people, culture, events and tickets remain the story the visitor came to discover.

The visual experience should resemble a carefully art-directed game environment: physical surfaces, believable contact shadows, purposeful character acting and occasional surprises. The interface still uses normal scrolling, real links, readable event names and immediately available controls. A visitor can buy a ticket without playing anything.

Three major moments carry the design: a cinematic arrival over the existing festival film; an open event stage where characters interact across the programme and artwork; and a sponsor light installation with exposed logos. Gallery photography receives its own collectible frame treatment. Quiet spaces between those moments make the more elaborate scenes effective.

Use one active narrative in a viewport, normally one main character and one supporting character. The full cast belongs to the ecosystem, not to every screen simultaneously. A character must have a reason to be in its location.

**2. References and the design decisions they inform**

| Reference | Relevant idea | Anazori interpretation |
| --- | --- | --- |
| [Bruno Simon's portfolio](https://bruno-simon.com/) | A navigable world with discoverable secrets | Characters remember discoveries; the public festival retains direct links and ordinary scrolling. |
| [Lusion: Choo Choo World](https://lusion.co/projects/choo_choo_world/) | Playful interaction and shareable creations | Optional discoveries lead to a personal festival postcard. |
| [Program: Spatial Festival](https://program.studio/work/spatial-festival/) | An interactive identity connected to editable festival content | The visual stage derives from the same CMS records as the programme. |
| [Pentagram for London Design Festival](https://londondesignfestival.com/stories/framing-ldf-by-pentagram) | Framing that spotlights partners and imagery | Sponsor marks remain clear while their surrounding light moves; photographs retain visual priority. |

These are research references, not finished Anazori screens or code to copy wholesale. The composition, choreography and frame system below are original design proposals. Referencing a character's official page establishes visual reference material; it does not establish availability of a deployable model or asset permission.

**3. Resolve the five annotated problems**

| Existing element | New direction |
| --- | --- |
| Orbital event map, category spheres and stacked boxed links | Open typographic programme beside a single theatrical artwork stage. Every published event remains visible. |
| SBI/Red Bull preview cards with orbital rings | One continuous light installation. No individual card shells, corner badges, orbit rings or card footers. |
| Gallery category toolbar | Removed. Photos open directly into the existing viewer. |
| Repeated thin rectangular gallery borders | Art-directed metallic dragon-scale frames with distinct corner sculpting and a restrained parchment caption rail. |
| Repeated decorative asterisk | Contextual character cameos or intentional empty space. Do not replace every asterisk with the same character sticker. |

Preserve the previously accepted Culture × Tech colours and record composition, the sponsor invitation bento, the top-positioned navigation, text-only navigation labels, mobile sign-in access, clean account pages and once-per-visit entry sound. Changes to the sponsor logo presentation do not require replacing the invitation bento.

**4. Shared art direction**

Use midnight ink #090D19 as the public world's resting background. Warm ivory #F6E8D0 gives the sponsor and storytelling sections a different temperature. Electric mint #91F3DF and lilac #B59CFF preserve the existing identity. Burnished brass #B89563 anchors fantasy metal; ember coral #FF8C71 introduces warmth; deep plum #35203F gives shadows depth.

Each scene uses one main accent and one supporting accent. Character colours and sponsor logos retain their source colours. Avoid a rainbow applied indiscriminately to every heading, frame and button. Check actual text/background combinations rather than assuming that every accent is a readable text colour.

Keep Monument Extended for ANAZORI and major event titles, with carefully sized line breaks. Use the established readable body face for descriptions, fees, dates and forms. Serif accents remain in cultural/editorial copy where already effective. Do not give every fictional universe its own font.

Default desktop layout: a 12-column content grid, generous outer margins, restrained copy width and a maximum content width around 1440px. Use a consistent spacing scale, but allow character artwork to extend into reserved gutters. At 320–767px use one content column and an art ledge reserved in normal layout. At tablet sizes reduce overlap before reducing text size.

The website should not display these planning labels as extra subheadings. Visitors need a short main heading, the content and the action. Repeated eyebrow labels, fabricated system codes and decorative status readouts should disappear.

**5. The character casting sheet**

| Character | Role and location | Signature behaviour | Restraint |
| --- | --- | --- | --- |
| Bob and Stuart, Minions | Festival stage crew; programme edge and gallery invitation | Carry a cable, adjust a small light, celebrate a discovery | Use specific character reference sheets; avoid an interchangeable generic yellow figure. |
| Doraemon | Guide between the introduction and programme | Opens the Anywhere Door and passes a light capsule between sections | One clear portal gag, rather than an always-running portal loop. |
| Pikachu | Power technician for Game of Codes and Workshops | A cheek spark travels through a seam and illuminates the selected event artwork | Electricity stays away from reading text and inputs. |
| Gengar | Gaming host for Joystick | Emerges from a shadow behind the artwork plane and waves | Playful timing; no sudden full-screen jump scare. |
| Charizard | Aerial guest over the event stage | One distant fly-by and an ember wake when the scene is discovered | Tail flame and identity stay faithful to the selected reference version. |
| Original mythological dragon | Keeper of the gallery and its metalwork | Breath gently warms the scales along a frame; a wing forms a bridge between photographs | Give this dragon an original, stable design rather than borrowing an inconsistent model per scene. |
| Totoro | Quiet companion beside memories and festival information | A slow breath and a leaf moving in the section gutter | A calm resting scene with enough empty space. |
| Sonic | Guide to sporting energy and Futsal | A short run along a decorative baseline after the event is selected | He never moves the link, changes focus or controls the visitor's scroll speed. |
| Stitch | Creative helper for Tulika | Catches a loose colour ribbon and pins it to an artwork edge | The ribbon decorates the scene, not the sponsor logo. |
| Kirby, optional later cameo | Companion to the personal festival passport | Briefly carries a cosmetic discovery badge into its slot | Add only after the core cast is coherent and within the performance budget. |

Official reference starting points include [Illumination's Minions page](https://www.illumination.com/movie/minions/), the [Pokémon Pokédex](https://www.pokemon.com/pokedex/), [Doraemon Channel](https://www.dora-world.com/) and [SEGA's character directory](https://sonic.sega.jp/SonicChannel/character/). Select a single visual version per character before producing animation; modern and classic variants must not be accidentally mixed.

**6. The character fidelity pipeline**

Begin with a character sheet: front, three-quarter and side reference; silhouette; face landmarks; material references; proportions; palette; hand/foot shape; and identifying accessories. Freeze this sheet before animation.

Use authorised source models or artwork where available. If a model must be produced, it needs a manual modelling, rigging and art review process against that reference. A generated bitmap is not evidence of exact character accuracy. Do not replace a missing asset with an approximate face and call it finished.

For each deployable character, prepare an idle pose, entrance, reaction, interaction and exit where the scene requires them, plus a static poster. Export only the actions used on the site. The runtime should not download an entire unused animation library.

Use one shared lighting setup: a warm key from the upper left, a cool soft rim, and environment colours borrowed subtly from the current section. Add local contact shadows where feet, hands or a body touch the layout. Keep the official material style: metallic goggles should reflect differently from fur, cloth or a smooth cartoon surface.

Review silhouettes at thumbnail size, faces at production size, and slow-motion animation for hand clipping, limb intersections, eye drift, incorrect finger/ear count, floating feet, texture seams and broken expressions. Source art must have sufficient resolution for its largest display size; arbitrary upscaling is not a quality substitute.

Asset records need an identifier, source/version, usage status, image dimensions, scene assignments, baseline, attachment points, fallback poster and motion variants. Attachment points include feet, hand grip and eye direction. These make interaction with the surrounding layout deliberate.

If an approved 3D model is unavailable, a faithful 2D cutout can be used as an explicitly flatter treatment. Perspective tricks cannot turn it into an anatomically correct 3D model. The production scope of the most ambitious scenes depends on the assets actually available.

**7. Arrival: the first screen**

The existing festival film remains the environment. The ANAZORI V16.0 title is visible immediately; loading animation never hides the page. A restrained coloured rim passes behind the wordmark over roughly 900ms, leaving a stable readable title.

Navigation stays in its current top document position with transparent dark glass, a thin illuminated edge and text-only links. It scrolls away with the page as previously requested. The mobile header always includes a usable sign-in link and menu control.

A Minion is already resting at the lower edge of the hero, outside the title and main action. Once the first scene is ready, it plugs a cable into the wordless energy beam beneath the hero. The beam carries that energy towards the introduction. This is the first physical connection between sections.

Keep the main ticket/event link available from first paint. Fast scrolling cancels the entrance into its resting pose. The character never blocks navigation, film content or the main headline. Returning visitors see the settled composition instead of the same introductory performance.

**8. Introduction and the first portal**

Retain the story on the left and the official 16:9 film on the right. The film has a refined mechanical frame, distinct from the gallery's dragon metalwork. Doraemon stands on a small ledge outside the film frame.

As both the end of the introduction and the beginning of the events section become visible, he places the Anywhere Door near the edge of the story column. A second opening appears at the upper edge of the event stage. A small light capsule crosses the threshold and exits beside Pikachu.

The capsule is a foreground prop with its own shadow. Its path runs through reserved gutter space and behind content where necessary. The film player remains completely usable. When the official film is absent, preserve the existing honest coming-soon state rather than presenting a fake play action.

On mobile the two anchors are vertically arranged. Use a short downward hand-off, not a long diagonal flight across text. If the visitor scrolls past quickly or reverses direction midway, settle the capsule at its destination without replaying a visibly broken half-scene.

**9. Replace the event explorer completely**

The new composition is an open programme with one artwork stage. A short heading such as “Find your moment.” introduces it. Every event title is a real link; the visitor never has to decode a map or select a category before seeing the programme.

Desktop: the left six columns contain seven large title rows; the right six columns form a borderless theatrical space. Rows contain the title, a compact factual status and an action. Light hairlines provide rhythm without enclosing each event in a box. The category and confirmed fee can appear as useful text, never as unnecessary icon badges.

Current programme mapping:

| Event | Stage treatment |
| --- | --- |
| Game of Codes | Pikachu powers a mint-lit physical circuit surface. |
| Prativa | Existing performance photography under warm stage light; a Minion adjusts a spotlight off to the side. |
| Joystick | Gengar emerges behind a violet stage ledge. |
| Futsal | A real pitch or ball composition with Sonic's brief baseline run. |
| Workshops | Doraemon opens a small gadget tray near the artwork. |
| Paper Presentation | A carefully lit folio and floating sheet motion, with no character needed in the centre. |
| Tulika | Stitch catches a coloured ribbon beside real creative imagery. |

Hovering or keyboard-focusing a title updates the stage. The active title remains still and readable; a light marker moves to its row. The art transitions in approximately 250–450ms. Selecting an event navigates immediately to its existing detail page; navigation does not wait for the character performance.

All seven titles stay visible in the semantic page. Upcoming events retain “Programme preview” and their existing interest path. Show “Get ticket” only when registration is genuinely open; read prices, team size, dates and availability from the CMS/backend. Never invent availability to complete the visual design.

Mobile: seven vertical event entries with sufficient touch targets and no horizontal drag requirement. A compact artwork strip can change as the nearby entry comes into view. A single tap on an event opens it. Category counts, if retained anywhere, remain factual and secondary. They do not become another mandatory filtering interface.

**10. A complete interaction across two content areas**

The event scene contains one authored Minion/Pikachu sequence:

1. A Minion on the programme-side ledge notices the unlit stage.
2. It throws a loose cable loop towards Pikachu on the separate artwork platform. The loop catches an empty connector beside Pikachu, rather than wrapping around his body.
3. Pikachu investigates, then gives the connector a small electrical charge.
4. Light travels along the cable through the space between the two layout areas.
5. The event stage illuminates; the Minion briefly rocks backwards, regains balance and looks pleased.
6. Both settle. Subsequent hover changes use small reactions rather than replaying the entire sequence.

The proposed duration is four to six seconds, once per visit when comfortably in view. It never controls data loading. If interrupted by a navigation, dialog, rapid scroll or hidden tab, it stops cleanly.

Cross-section acting uses layout anchors rather than hard-coded screen coordinates. Recalculate anchors after fonts/images resize and when the viewport changes. Cache measurements outside animation loops. Separate background, actor-behind, content, actor-in-front and interface layers. Most decoration has pointer-events disabled; a deliberately interactive character has a real, labelled button.

**11. Culture × Tech remains a recognisable resting point**

Preserve its warm colour blend, culture/technology typography, record and frequency interaction. This is already an accepted design and should not be rebuilt as another portal scene.

Replace the small record asterisk with a tiny character cameo positioned at the outer edge of the record apparatus. It must not cover “ANAZORI V16.0” or the Culture lettering. A Minion can briefly lean towards the record needle, or the original small dragon can listen from a ledge. Choose one, then reuse its established lighting.

The record's controls retain their names and keyboard behaviour. Character reactions are visual feedback to an already completed input; they never introduce an extra required click. Maintain the mobile clipping fixes and stable text visibility.

**12. Sponsors: an open light installation**

Remove the individual card backgrounds, rounded containers, numbered corners, card footers and orbit rings. Keep one continuous warm-ivory section with two large sponsor marks in open space for the current preview.

The SBI and Red Bull logos sit on a shallow shared visual horizon. A broad, soft ribbon of light travels behind them. It creates a brief blue reflection around SBI and an amber-to-red reflection near Red Bull, then settles into a subtle ambient glow. The logos themselves retain their true proportions and colour. A faint reflected copy beneath each mark can add depth without becoming another frame.

Both brands are visible immediately. Proposed entrance: 0–0.8s, light enters; 0.8–1.6s, the first reflection builds; 1.6–2.4s, it reaches the second brand; 2.4–3.2s, the scene settles. Hover/focus can shift the surrounding light by a few pixels. It should feel like a miniature stage installation, not two items floating randomly in boxes.

For a larger sponsor list, use an open sequence of logos with generous spacing and the same shared light field. Confirmed sponsorship tiers can determine hierarchy; equal tiers receive comparable visibility. Always provide a stable readable set of logo links. Automatic movement pauses on hover, keyboard focus, reduced motion and the site's motion control.

Use clean supplied SVGs or sufficiently large transparent images. The current small SBI raster and CSS approximation of the Red Bull wordmark are preview limitations, not final brand assets. Keep the preview disclaimer until sponsors are confirmed. Do not put a character's face inside a brand mark or visually imply a character-brand partnership.

Retain the invitation bento below this installation. Remove its repeated asterisk and use a small bespoke prop or a cameo already established in the story. The sponsor section must remain attractive with one, two or many actual CMS records, and with a logo missing.

**13. Gallery: a different frame language**

The toolbar is gone; the first photographs begin directly after the introduction. Preserve authentic photos, captions and the existing keyboard/swipe lightbox. The public interface keeps neutral memory titles and sequence numbers instead of highlighting the old edition.

Use a sculpted metal frame: 10–14px on desktop and 6–8px on mobile. Its outer edge is dark antiqued bronze; overlapping scales catch restrained warm highlights; a narrow inner bevel separates the image from the metal. Two corners carry small sculpted dragon claws or wing joints. The other corners remain calmer so every frame does not look equally busy.

A slim parchment-coloured caption rail sits beneath the image, with dark readable text. It belongs to this gallery system only. Alternate two predetermined frame variants within the same family rather than randomly choosing unrelated ornament for every photo.

Use modular corners and repeating edge sections so scaling does not stretch a dragon head or warp scales. Keep the photograph rectangular and undistorted. Photo focal points remain editable; landscape and portrait images must each receive a suitable composition.

Hover/focus: one specular streak passes across the metal, the image scales at most about 1.015, and the open action becomes clearer. Touch: a tap opens the lightbox directly. No continuous rotation, waving photo surface or character covering a face.

Between two photographs, the original dragon rests across a reserved gap. Its near wing overlaps one frame; its tail passes behind the adjacent frame. An optional click on the dragon gives a warm breath that illuminates both frames in sequence. In the lightbox the dragon disappears and the photograph takes the whole stage.

**14. The wider fantasy construction system**

Use three distinct frame families: mechanical glass for navigation/official film; restrained edge accents for event facts; sculpted dragon metal for gallery photographs. Their shared palette and lighting create continuity without repeating the same corner graphic across everything.

Dragon frames are a material system, not hundreds of animated DOM scales. Build them from optimised corner artwork and tileable/nine-slice edges, or static geometry baked into a light texture. Animate a small highlight layer above the metal. Original dragon artwork can be commissioned/rendered independently of the licensed character cast.

Elemental connectors belong in selected gutters: a mint energy seam from the introduction into events; an ember vein leaving the aerial dragon scene; a low-contrast vine around the quieter memory/visit area. A connector can visually replace an empty divider while retaining real CSS spacing underneath.

Runes appear only where they serve a discovery or mark an actual interaction. They are original decorative symbols, not fabricated Assamese writing. Local cultural lettering and motifs need accurate source artwork and review. On mobile most long connectors become short edge accents so they do not cross body copy.

**15. A finite, optional festival passport**

Offer a small “Festival passport” control in the menu or an in-flow discovery area, not a new floating mobile widget. Opening it explains what can be discovered and how progress is stored. It is optional and has no effect on admission, availability or ticket price.

Proposed 100-point structure for the current programme: exploring all seven event pages earns up to 35 points, opening a memory earns 15, discovering the story earns 10, visiting the people page earns 10, reading practical festival information earns 10, and four hidden runes earn five each. Each action counts once. Event weights normalise if the published programme changes.

At 25 points, the passport receives its first coloured seal. At 50, the chosen companion performs a new greeting. At 75, a cosmetic frame becomes available for a shareable postcard. At 100, a short group tableau appears and a completed festival postcard can be downloaded.

The postcard uses the festival identity and only assets approved for that export. It is visibly distinct from an entry ticket and has no ticket QR. Real ticket QR codes, personal details and payment information never enter public share images.

There are no streak losses, forced waits, purchase points or artificial scarcity. Store a versioned set of completed actions locally; if storage is blocked, the feature works for the current page/session. Cross-device sync is a separate opt-in feature, not an assumption. Client-side cosmetic progress never proves payment or attendance.

**16. Easter eggs with a purpose**

The loose cable: activating the Minion's connector button reveals the longer Pikachu scene once and awards one rune. The interaction is also reachable from the passport's accessible discovery list.

The shadow guest: activating an unusual shadow near Joystick reveals Gengar's greeting. The shadow has a discernible focus state and label; it is not an invisible click target.

The sleeping guardian: clicking the gallery dragon warms two frames and reveals another rune. Repeat clicks during the action do not stack more particles or audio.

The missing leaf: Totoro's leaf is visible beside practical information; finding it completes a small story already hinted at in the memories scene. The site never conceals essential FAQ content behind the leaf.

A keyboard sequence can optionally trigger a harmless retro palette vignette, but the same effect must be available through a labelled passport action. Returning visitors can see one alternate greeting based on previously discovered scenes. These are simple deterministic states, not a claim that the site understands the visitor's personality.

**17. Behaviour that responds to the visitor**

Slow exploration allows a complete scene to play once. Rapid scrolling cancels it into a composed resting state. Pointer movement creates a very small local gaze/head response only while that character is visible. Touch devices use a short reaction to an intentional tap instead of imitating hover.

Keyboard focus can trigger the same artwork preview as pointer hover without moving the focused control. Typing into a form quiets nearby nonessential motion. Opening a dialog pauses background performances. Returning from another route restores the settled scene and relevant optional discovery state.

Use explicit states: dormant, ready, entering, idle, reacting, settled and suspended. Each scene has a cooldown and a play-once flag. Each transition has an interrupt path. Duplicate event listeners, overlapping timelines and repeated sound on history navigation are release failures.

Preserve the current one-shot home entry sound and native video controls. The cast is silent by default. There is no floating mute button and no new automatic looping music. Browser autoplay restrictions still apply.

**18. Motion and mobile performance specification**

Build the base composition as server-rendered HTML/CSS, with real event links present before JavaScript executes. Layer animation onto that content. Use CSS or Web Animations for simple movement, the existing animation tooling for authored sequences where useful, and a shared optional 3D renderer only when an actual 3D interaction requires it.

Do not create a WebGL canvas for every event, sponsor or gallery image. For many character actions, a carefully rendered short clip from the approved model is sufficient. Prepare tested media formats and static posters rather than assuming alpha-video support is identical across browsers. Reserve dimensions to avoid content shifts. Decode one upcoming scene, not the whole cast at load.

Prefer transform/opacity motion and profile exceptional effects. Large animated blurs, filters and repeated layout reads need particular scrutiny. The reasoning is grounded in [web.dev's animation performance guide](https://web.dev/articles/animations-guide). Offscreen and hidden-tab scenes stop. Remove temporary compositing hints when they are no longer needed.

Proposed additional character-system budget: about 60KB compressed orchestration code; up to 150KB for the first static character poster; up to 1.5MB compressed for an active scene; no more than roughly 64MB of additional decoded character textures on the baseline mobile tier. These are starting budgets to validate with actual assets, not measured properties of the current site. Compressed file size alone does not predict texture memory.

At small widths reserve roughly 100–160px for a cameo rather than overlaying text. Keep primary buttons comfortably touchable. No scroll capture, forced horizontal navigation or animation-dependent text reveals. A whole scene can use prebaked lighting while preserving the approved character shape and colour; stronger devices may receive live parallax and richer reflection.

Target stable 60fps on the agreed baseline phone and allow higher refresh rates where the device supports them. A universal 120fps guarantee is not credible. Measure cold/warm loads, sustained scrolling and thermal behaviour on real low-end Android hardware as well as desktop emulation.

Field goals are p75 LCP at or below 2.5s, INP at or below 200ms and CLS at or below 0.1, segmented by mobile/desktop. These are the published [Core Web Vitals thresholds](https://web.dev/articles/vitals); they complement frame-time measurements rather than replacing them.

**19. Accessibility and dependable navigation**

Reduced-motion mode presents the completed art composition with instant state changes. The existing motion control pauses all scene systems consistently. Avoid rapid flashes and maintain readable text on every frame of an effect.

All essential actions are normal links/buttons with keyboard focus. Decorative sprites are hidden from assistive technology. A character that actually responds to input has a useful accessible name and equivalent non-pointer interaction. Announce completed discoveries briefly; never announce animation frames or every scroll movement.

The event catalogue works with JavaScript unavailable. Media failure leaves a readable event stage and usable links. A missing character produces an intentional empty ledge or poster, not a broken-image icon. A missing official film retains its coming-soon state. Long event titles, zoomed text and narrow screens must not be clipped by ornamental frames.

Login, account tickets, registration and payment screens stay calm. Characters can appear as a small completion celebration only after a real verified success, without hiding reference numbers, errors, receipts or the QR code. The Organising Studio continues to prioritise clear data and scoped permissions.

**20. Fit this into the existing repository**

Replace `includes/world-atlas.php` with a new programme-stage template, preserving the live `$festival['events']` source and `/event.php?name=...` routes. Add a narrowly scoped stylesheet and module for the new stage. Remove obsolete atlas import/hooks only after checking their other uses.

Update the sponsor markup in `index.php` for both sample and real CMS-record paths. Share the open-stage renderer so a published sponsor does not fall back to the old cards. Preserve the explicit unconfirmed-preview label and the separate invitation bento.

Extend `gallery.php` with the distinct frame wrapper without changing the existing lightbox contract (`data-full`, `data-caption`, button names and image alt text). The filter markup has already been removed. Audit decorative asterisks in page templates, CSS generated content and seeded CMS symbols, avoiding a destructive global database replace.

Keep scene logic in one bounded director module with reusable visibility, motion-preference and history lifecycle hooks. Integrate it with `src/ambient-motion.js` and `src/scroll-motion.js`; do not add a competing animation loop for the same elements. Remove superseded selectors from the layered CSS instead of accumulating another stack of overrides.

Add a collapsible “World & motion” Studio area for scene enable/disable, character asset assignment, static preview and mobile preview. Partner records get logo, destination, tier and confirmation state. The CMS exposes safe predefined options, not arbitrary executable shader/JavaScript fields. Existing staff permissions govern publishing.

Public decorative assets can be cached on a CDN. Private account, payment, receipt and Studio responses must retain their privacy/caching rules. Visual enhancements do not change ticket generation, coordinator event access, financial allocations or server-side payment verification. Do not turn local passport progress into an authority for real registration rewards.

**21. Delivery order and proof required**

First, create a small visual reference board and freeze the cast versions, palette and scene hierarchy. Produce still compositions at 1440px and 390px for the event stage, sponsor installation and first two gallery frames. Static quality must be convincing before animation is added.

Second, complete the character asset audit and one production-quality test asset. Validate facial accuracy, contact shadow, transparent edges and mobile memory cost. Use this asset to test the shared rendering approach before producing the rest of the cast.

Third, implement the event programme layout with all seven working links and real statuses, then the sponsor stage and gallery frames. Verify those sections as complete static experiences, including empty records and long content.

Fourth, build the single Minion/Pikachu scene and the Doraemon hand-off. Test interruption, resize, mobile layout and browser history. Add the quieter dragon/gallery and expanded-cast moments only after these sequences are reliable.

Fifth, implement the optional passport, unique-action tracking and postcard export. Keep the default festival experience complete without opting in. Add Studio controls and asset preview for organisers.

Finally, profile actual devices and validate keyboard navigation, touch, reduced motion, missing media, slow connections, hidden tabs, back/forward navigation and all ticket paths. Use existing browser suites for regressions and add targeted tests for new stateful behaviour. Review screenshots and short recordings at 320, 390, 768, 1024 and 1440px.

Acceptance means no hidden event links, clipped titles, obstructed logos or photographs, false sponsor claims, repeated unsolicited sound, runaway offscreen animation or unverified ticket success. Character assets pass visual review against their selected source sheets. Frame-time and Web Vitals results are reported with the devices and conditions used, rather than described as universally lag-free.

**22. Implementation status for this planning pass**

The gallery category toolbar was removed from `gallery.php`; original photo records, categories in the CMS and the viewer remain. The other redesigns and the character ecosystem are specified here and remain proposed work. This document does not claim that reference assets have been licensed, character models delivered, future performance targets reached or the redesign deployed.

Validation of the completed gallery change: `php -l gallery.php` passed. The existing `node tests/flagship.mjs` suite passed all seven groups, covering public responsive layouts, mobile navigation, isolated interest submission, gallery keyboard navigation, reduced-motion/JavaScript fallbacks, runtime errors and automated accessibility checks. These results validate the current build, not the future scenes described above.
