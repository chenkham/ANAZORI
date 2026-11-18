# Rendering and image optimization

The artwork, scene timing, animation choices, keepsake dimensions and download settings remain intact.

- The keepsake renderer uses a worker with OffscreenCanvas where supported. It keeps one rendering request in flight and one latest queued request, closes transferred bitmaps and terminates on navigation. Initialization failures, unsupported browsers and stalled workers use the existing main-thread renderer.
- Preview rendering pauses when hidden or offscreen and resumes when visible. Explicit pause and accessibility preferences remain effective. Export uses a separate renderer and retains 1920 × 1080, 30 fps capture and the existing bitrate.
- `src/rendering84.css` uses content visibility only on fixed-size, clipped artwork windows. Whole sections, forms, anchors and decorative overflow remain outside those containment rules.
- `scripts/responsive-images84.py` creates lossless public-image WebP variants with retained colour profiles. Templates use local-file srcsets while retaining original full-resolution images. Animated images and private participant uploads are excluded. The optional GD upload path skips metadata it cannot preserve and safely falls back to the original.
- Worker bundles have content-hashed names. Rebuilt public and registration entry scripts use file modification times in their URLs so cached entries do not import stale code. Prior lazy chunks retain the existing 24-hour grace period.

## Maintenance

Run `python scripts/responsive-images84.py` after adding large public images, then `npm run build` after browser-source changes. The scripts retain originals. Responsive reports and worker identity are written to `output/performance84/`.

## Verification and limits

Worker queue/cleanup, animation lifecycle, task scheduling and public-image tests passed. Browser tests compared 12 main-thread/worker frames at both render resolutions; layout and artwork matched visually. There are small browser-renderer antialiasing differences (mean channel error below 0.09/255), so the outputs are not byte-identical. Unsupported-worker and failed-worker fallbacks passed.

A real keepsake download was verified as a playable 1920 × 1080 MP4 of approximately 12 seconds. At mobile width, the visible wordmark selected a roughly 59 KB responsive image instead of its roughly 591 KB original. These are browser checks on this computer; no universal frame-rate guarantee or physical low-end-device benchmark is claimed.

Google participant identity/profile and account matching tests passed alongside these changes. A real Google OAuth consent/callback roundtrip still needs verification with the configured Google client by its account owner.
