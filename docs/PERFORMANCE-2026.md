# Mobile rendering — release 2026.27

The festival artwork, colour palettes, borders, font choices, video files, particle count, particle resolution and visible animation cadence are retained. Text stays fully opaque throughout its moving entrance, so the reader no longer waits for a fade to finish.

## Rendering changes

- Supported browsers use one native root `ScrollTimeline` for scroll choreography. Additive transform keyframes preserve existing card positioning, vinyl tilt and CSS spinning. JavaScript no longer seeks every animation on every scroll event. The reading-progress bar also uses a native timeline.
- Browsers without that API retain reversible scroll motion using one scheduled frame, cached natural layout geometry and unchanged-value checks.
- Only nearby scenes keep scroll animations attached. Separate 240px entry and 360px exit margins prevent a moving card from repeatedly cancelling/recreating itself at an observer boundary. Hidden event categories release their animations and update geometry when selected.
- Decorative CSS animations sleep outside the viewport and when the document is hidden. They resume at their existing phase when visible. The atlas light sweep has its own transform layer rather than an inherited CSS variable that invalidates the whole section. Border glints travel the same path using translation instead of animating layout.
- Removed WebGL context probes from the ordinary video/static intro. Cached the particle floor path, canvas backing dimensions and pointer geometry. Vinyl pointer events are batched to one refresh.
- Countdown updates write only changed values and run a timer only while a live/upcoming countdown is visible. Unannounced and ended clocks have no repeating timer.
- Motion controls, reduced-motion settings, Save-Data, keyboard focus, print preview and persisted-page lifecycle handling remain functional. Account, checkout and Studio still receive no scroll choreography.

The native timeline implementation follows the [Element.animate timeline/range API](https://developer.mozilla.org/en-US/docs/Web/API/Element/animate) and [ScrollTimeline API](https://developer.mozilla.org/en-US/docs/Web/API/ScrollTimeline). Transform animation and avoiding layout/paint work follow the [browser rendering guidance](https://web.dev/articles/animations-and-performance).

## Measured local comparison

One baseline run of release 2026.25 and one final run of 2026.27 used headless Chromium, a 390×844 viewport, DPR 1, 6× CPU throttling, the same local database/asset files, motion enabled, sound disabled, and a 12-second full-page down/up scroll. Original video and graphics were loaded; none were blocked or replaced for the benchmark. Browser suites did not run concurrently with profiling.

| Diagnostic | Before | Final |
| --- | ---: | ---: |
| Long main-thread tasks (>50ms) | 119 | 23 |
| Total long-task duration | 10,245ms | 1,676ms |
| Sampled animation frames | 152 | 463 |
| Median frame interval | 66.7ms | 16.7ms |
| 95th-percentile frame interval | 166.6ms | 50.1ms |
| Style calculation time | 3,962ms | 2,433ms |
| Layout time | 280ms | 180ms |
| Script execution time | 854ms | 685ms |
| Uncaught browser errors | 0 | 0 |

Long-task time decreased by approximately 84%. The frame samples measure the test's `requestAnimationFrame` callbacks during scripted scrolling, not physical display output. Trace durations overlap and must not be added together. These are individual diagnostic runs, not statistically controlled device benchmarks. CPU throttling does not reproduce a low-end phone's GPU, memory, network or browser. No universal zero-lag or 120fps claim is made; physical Android/iOS testing is still needed for those devices.

Raw results and Chrome traces are saved in `.local/performance/before.json`, `final.json`, `before-trace.json` and `final-trace.json`. Intermediate profiles are preserved separately. `.local` is excluded from version control and blocked by both development and Apache routes.

To record another comparable profile, close other browser tests, run `npm run build`, then `npm run profile:mobile -- device-check`. The script starts an isolated local PHP server on port 8111 and writes the label's JSON and trace under `.local/performance`. Its fixture database is separate from the real festival database. It closes its browser/server afterward.

## Verification

Public integration, public browser/accessibility, circular event navigation, responsive typography and participant/payment/ticket suites passed. Browser checks cover motion on/off, native and forced-fallback timelines, forward/reverse scrolling, immediately readable text, keyboard navigation, live CMS event counts, widths from 360 to 1440px, missing WebGL, JavaScript disabled, Save-Data and lifecycle restoration. The native print and idle observer-boundary regressions are also covered. Persisted-page lifecycle is simulated because the test Chromium configuration disables real bfcache.

Local screenshots confirm the complete Culture heading, upright ANAZORI V16.0 vinyl label, count-bearing category circles and retained sponsor bento. Payment tests use a mock gateway and private test outbox; no real charge or email is sent. This pass measures client rendering, not production concurrency capacity. Hosting validation remains in `FESTIVAL-DEPLOYMENT.md`.
