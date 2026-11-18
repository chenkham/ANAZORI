# Mobile rendering improvements

Applied to `the local Anazori project directory`. The deployable files in
`src/assets/2026` were rebuilt with `node scripts/build.mjs`.

## Changes

- `frontend/voxel-world70.css` moves the same fixed viewport gradients from the
  body onto the existing scenery layer. The layer is composited independently,
  avoiding a fixed body background that can cause document repainting during
  scrolling. Scenery, movement, gradients, and accessibility fallbacks remain.
- `frontend/festival-scenes.js` decodes automatic SVG performances within 320 px
  of their scene. Actual playback still follows the original visibility and
  motion controls. Hidden carousel panes, closed dialogs, and interaction-only
  performances remain deferred. Decodes share the existing task queue and are
  guarded against background tabs, reduced motion, and navigation.
- `frontend/motion-card.js` retains the ticket's static materials, typography,
  and logos per face and per ticket data. Its foil, glow, waveform, perspective,
  frame timing, output resolution, and export settings remain. Editing a name
  invalidates the cache for both faces. The existing worker and fallback use the
  same renderer.

The site already uses native scrolling, compositor transforms, Intersection
Observers, offscreen animation suspension, responsive WebP images, compressed
text assets, and a worker for keepsakes. These paths are retained. No additional
scroll library, animated artwork replacement, or global `will-change` was added.

## Measurements

Chromium, 390 x 844 viewport, DPR 3, sixfold CPU slowdown, motion enabled,
warmed assets, localhost. Each run traverses the full page down and back over
12 seconds. All have the same 10,233 px scroll extent and no JavaScript errors.

| Run | Frames sampled | p95 frame interval | Frames over 34 ms | Main-thread task time |
| --- | ---: | ---: | ---: | ---: |
| Original, first run | 514 | 50.0 ms | 35 | 11,362 ms |
| Original, repeat | 594 | 33.4 ms | 13 | 11,252 ms |
| Optimized, first run | 614 | 33.4 ms | 21 | 10,184 ms |
| Optimized, repeat | 628 | 33.4 ms | 12 | 9,977 ms |
| Final, interaction-only preload excluded | 612 | 33.4 ms | 15 | 10,492 ms |

Main-thread task time fell in every optimized run. The final run uses about
7-8% less than the two originals. Slow-frame counts vary with desktop load;
these measurements do not establish a guaranteed frame rate on a phone.
Programmatic traversal measures main-thread rendering pressure, while the
separate integration test exercises actual touch input.

The final ticket benchmark rendered 90 frames in 1,237 ms versus 1,397 ms
originally, about 11% less time. It uses fresh canvases separate from pixel
readback. Eight frame comparisons cover both sides, turning, glow, foil,
waveform, and changed names: zero pixels differed by more than 20/255, and mean
channel error stayed below 0.001/255. Mobile and desktop stationary screenshot
comparisons also stayed below 1/255 mean channel error.

Raw results and screenshots are in `.local/mobile94`. These are desktop mobile
emulation results; physical Android and iPhone hardware were not available.

## Verification

Passed:

- `node tests/mobile-rendering94.mjs`: nine checks for fast touch swipes and
  reverse scrolling, retained scenery, original animated characters and vinyl,
  carousel controls, reduced motion and browser restoration, built keepsake
  playback and edited names, four responsive widths, ScrollTimeline fallback,
  and original appearance. No page errors or horizontal overflow.
- `node tests/motion-card-cache94.mjs`: authored-frame comparisons, cache
  invalidation for changed names, and an informational rendering benchmark.
- `node tests/animation-lifecycle82.mjs`: visible animations continue during
  scrolling; offscreen, background-tab, back/forward, and preference handling.
- `node tests/keepsake-worker84.mjs`: latest-frame queue, bitmap release,
  navigation cleanup, and interrupted initialization.
- `node tests/keepsake-video.mjs`: MP4 capability and container validation.
- `node scripts/build.mjs`.

The browser checks only read public pages and use browser-local inputs. They do
not submit registration/payment forms or change CMS content.

## Reproduce and recover

With the local preview running at `http://127.0.0.1:8000`:

```powershell
node tests/mobile-rendering94.mjs
node tests/motion-card-cache94.mjs
node scripts/profile-mobile94.mjs comparison-before --baseline
node scripts/profile-mobile94.mjs comparison-after
```

Run browser profiles sequentially. `ANAZORI_QA_BASE`, `ANAZORI_QA_CPU`, and
`ANAZORI_QA_DPR` can override profiling conditions. Keep conditions and content
the same for comparisons. Baseline source, entry, CSS, and retained lazy chunks
are in `.local/backups/mobile94`; they remain private local recovery files.
Restoring the three original frontend files and rebuilding reverses this pass.

Upload the rebuilt `src` contents using the normal deployment process. Existing
PHP asset versioning refreshes entry URLs; upload all generated chunks together
with `site.js` and `public.css`.
