# Mobile scroll scheduling

This pass keeps the existing artwork, blur/glow styles, animation keyframes,
durations, particle count and rendering resolution. It changes browser work
scheduling rather than introducing a reduced mobile design.

- Reading progress uses a native ScrollTimeline where supported. Its fallback
  caches document height and invalidates it after layout, font, content and
  viewport-width changes instead of reading scrollHeight on every scroll.
- Scroll-driven scenes share ancestor-offset measurements. All geometry reads
  finish before animation writes. Height-only viewport resizing reuses cached
  geometry; ResizeObserver still tracks actual element-size changes. Native
  animation ranges are only assigned when their values change.
- Particle-canvas sizing is coalesced into one animation frame. Mobile toolbar
  resizing skips canvas measurements when its actual box and pixel density are
  unchanged. Existing particle drawing and timing are retained.
- Character visibility updates share cached image/owner references and one
  dialog-state lookup per update. Repeated notifications share a pending
  animation start instead of attaching duplicate decode callbacks.
- Card hover lighting attaches pointer listeners only when a hover-capable,
  fine pointer is available and motion is active. Touch-only devices do not
  execute that delegated hover handler during gestures.
- Navigation, background-tab suspension and back/forward restoration retain
  cleanup and resume handling.

Browser files were rebuilt. Automated tests, browser checks and physical-device
profiling were not run for this pass, as requested by the user. Actual mobile
scroll performance remains for the user to assess on their devices.
