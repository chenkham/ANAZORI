export function initIntroVideo() {
  const video = document.querySelector('#intro-video');
  if (!video) return;
  const automatic = video.dataset.autoplay === '1';
  const connection = navigator.connection;
  let visible = false, suspended = false, stopped = false, userPaused = false, internalPause = false, generation = 0;
  const eligible = () => !stopped && !suspended && visible && !document.hidden && (!automatic || (!document.documentElement.classList.contains('motion-paused') && !connection?.saveData));
  function pause() {
    if (!video.paused) { internalPause = true; video.pause(); }
  }
  function sync() {
    generation++;
    if (!eligible()) { pause(); return; }
    if (!automatic || userPaused || !video.paused) return;
    const attempt = generation;
    video.muted = true;
    video.play().then(() => { if (attempt !== generation && !eligible()) pause(); }).catch(() => {});
  }
  const onPause = () => {
    if (internalPause) { internalPause = false; return; }
    if (eligible()) userPaused = true;
  };
  const onPlay = () => { userPaused = false; if (!eligible()) pause(); };
  video.addEventListener('pause', onPause);
  video.addEventListener('play', onPlay);
  const observer = new IntersectionObserver(entries => { visible = entries[0].isIntersecting; sync(); }, {threshold:.15});
  observer.observe(video);
  document.addEventListener('visibilitychange', sync);
  document.addEventListener('anazori:motion', sync);
  connection?.addEventListener?.('change', sync);
  function hide(event) {
    suspended = true; sync();
    if (event.persisted) return;
    stopped = true; observer.disconnect();
    video.removeEventListener('pause', onPause); video.removeEventListener('play', onPlay);
    document.removeEventListener('visibilitychange', sync); document.removeEventListener('anazori:motion', sync);
    connection?.removeEventListener?.('change', sync);
    removeEventListener('pagehide', hide); removeEventListener('pageshow', show);
  }
  function show(event) { if (event.persisted) { suspended = false; sync(); } }
  addEventListener('pagehide', hide); addEventListener('pageshow', show);
}
