# Lightweight festival characters

Release: 6 October 2026. Public asset version: **2026.42**.

## Placements

Keep the accepted Culture × Tech colours, vinyl and frequency control. Coco is the small guitarist beside the record. Prativa uses the previous guitar Minion, Stuart. Pikachu belongs to the original chase and the static Events introduction; it is absent from Culture × Tech.

Game of Codes uses a transparent Roz vector rendition with a small terminal. Paper Presentation uses the supplied Baymax performance and a research folio. Workshops uses the supplied WALL-E/EVE performance. Joystick retains Gusion/BGMI, Tulika retains the dragon, and Futsal retains Sonic. Gengar is the gallery's quiet ghost; Charizard is the Joystick detail companion. Default templates use each cartoon identity at most twice; count both Stuart images together.

Stitch reacts to sponsor interaction beneath the exposed sample logos. The sponsor invitation bento retains its accepted colours and no longer has the round rings ornament. Totoro and Deadpool loop while their sections are visible. Baymax reacts to FAQ interaction. Link, Mario and Kirby belong to the optional festival passport. Brief entrance scenes replay when their section leaves and re-enters the viewport.

## Runtime

Mobile hides the desktop event index and shows one artwork pane with horizontal swipes, previous/next buttons, keyboard arrows and a position counter. Vertical scrolling is native. The no-JavaScript page retains access to all events.

Supplied animations are converted at build time to transparent native SVG/SMIL, preserving authored whole frames. Initial images are visible stills. Motion loads only for a visible selected scene or direct interaction. Offscreen sections, hidden tabs, reduced motion, Save-Data, motion-off and open dialogs use stills. No WebGL, 3D models, physics engine, production Lottie runtime or continuous JavaScript character loop is loaded.

The original Doraemon chase uses transparent sprite artwork because its source has raster layers. Existing Stuart/Pikachu pictures, approved Joystick art, gallery photos and the hero video remain. Roz, Link and Kirby are custom flat vector renditions, not official publisher exports; `assets/2026/vector/custom-sources.json` records that distinction. Supplied artwork provenance and hashes are in `assets/2026/vector/sources.json`.

SVGs are precompressed for the development router. Apache uses `.htaccess` compression. Vector export scripts are development tools; the site serves their completed assets. Keep source downloads intact. Character scenes are absent from participant checkout, dashboards and studio screens.

## Verification

Run `node tests/content-cast.mjs`, `node tests/supplied-scenes.mjs` and `node tests/festival-scenes.mjs`. Supplied-scene checks compare actual painted character poses, not only animation classes. Guards, transparent stills, chase ordering, responsive widths and character repetition are also checked.

The earlier mobile profile measured a 16.7 ms median frame interval at normal CPU speed. Under a fourfold CPU slowdown, complex SVG motion can still produce slower frames. Browser emulation is not a guarantee for every handset; check an actual medium-range phone before launch.
