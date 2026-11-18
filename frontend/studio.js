import './studio-editor79.js';
// Keep the operational navigation compact without making access depend on JavaScript.
const sidebar = document.getElementById('studio-sidebar');
const menu = document.querySelector('.studio-menu-button');
const workspaceBody = document.querySelector('.studio-body');

if (sidebar && menu && workspaceBody) {
  const root = document.documentElement;
  const compact = matchMedia('(max-width:950px)');
  const backdrop = document.createElement('button');
  backdrop.className = 'studio-menu-backdrop';
  backdrop.type = 'button';
  backdrop.hidden = true;
  backdrop.setAttribute('aria-label', 'Close studio navigation');
  backdrop.tabIndex = -1;
  document.body.append(backdrop);

  let closeButton = sidebar.querySelector('.studio-menu-close');
  if (!closeButton) {
    closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'studio-menu-close';
    closeButton.textContent = 'Close';
    closeButton.setAttribute('aria-label', 'Close studio navigation');
    sidebar.prepend(closeButton);
  }

  let open = false;
  root.classList.add('studio-enhanced');
  menu.setAttribute('aria-controls', sidebar.id);
  menu.setAttribute('aria-expanded', 'false');
  // Native details work with mouse, touch and keyboard, including without JS.
  const groups = [...sidebar.querySelectorAll('details.studio-nav-group')];
  groups.forEach(group => group.addEventListener('toggle', () => {
    if (!group.open) return;
    groups.forEach(other => { if (other !== group) other.open = false; });
  }));

  function setOpen(value, returnFocus = true) {
    const next = compact.matches && Boolean(value);
    const wasOpen = open;
    open = next;
    root.classList.toggle('studio-menu-open', open);
    menu.setAttribute('aria-expanded', String(open));
    backdrop.hidden = !open;
    workspaceBody.inert = open;
    sidebar.inert = compact.matches && !open;
    if (compact.matches) {
      sidebar.setAttribute('aria-hidden', String(!open));
    } else {
      sidebar.removeAttribute('aria-hidden');
    }
    if (open) {
      sidebar.setAttribute('role', 'dialog');
      sidebar.setAttribute('aria-modal', 'true');
      sidebar.setAttribute('aria-label', 'Studio navigation');
      closeButton.focus({ preventScroll: true });
    } else {
      sidebar.removeAttribute('role');
      sidebar.removeAttribute('aria-modal');
      sidebar.removeAttribute('aria-label');
      if (wasOpen && returnFocus) menu.focus({ preventScroll: true });
    }
  }

  menu.addEventListener('click', () => setOpen(!open));
  closeButton.addEventListener('click', () => setOpen(false));
  backdrop.addEventListener('click', () => setOpen(false));
  sidebar.addEventListener('click', event => {
    if (event.target.closest('a[href]')) setOpen(false, false);
  });
  document.addEventListener('keydown', event => {
    if (!open) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key !== 'Tab') return;
    const stops = [...sidebar.querySelectorAll('summary,a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]')]
      .filter(element => !element.hidden && element.getClientRects().length && !element.closest('[inert]'));
    const first = stops[0];
    const last = stops.at(-1);
    if (!first) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  compact.addEventListener('change', () => {
    setOpen(false, false);
  });
  setOpen(false, false);
}

// Event context normally changes with the explicit Go button. Opt-in auto-submit
// is restricted to the GET selector so it cannot submit editing/payment forms.
document.querySelectorAll('form.workspace-switcher[data-auto-submit="true"]').forEach(form => {
  if (form.method.toLowerCase() !== 'get') return;
  form.querySelector('select[name="event_id"]')?.addEventListener('change', () => form.requestSubmit());
});

// Secondary editors stay tucked away until needed. Move existing controls so
// form ownership, names, CSRF tokens and server-side permission checks survive.
document.querySelectorAll('.studio-main .upload-panel,.studio-main form>section.panel').forEach(panel => {
  const title = panel.querySelector('h2');
  if (!title) return;
  const details = document.createElement('details');
  details.className = `${panel.className} studio-disclosure`;
  if (panel.id) details.id = panel.id;
  const summary = document.createElement('summary');
  summary.textContent = title.textContent;
  title.remove();
  const content = document.createElement('div');
  content.className = 'disclosure-content';
  while (panel.firstChild) content.append(panel.firstChild);
  details.append(summary, content);
  panel.replaceWith(details);
});

function revealEditor(target) {
  for (let node = target; node; node = node.parentElement) {
    if (node instanceof HTMLDetailsElement) node.open = true;
  }
}
document.addEventListener('invalid', event => revealEditor(event.target), true);
function revealHash() {
  let id;
  try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
  if (!id) return;
  const target = document.getElementById(id);
  if (!target) return;
  revealEditor(target);
  target.scrollIntoView({block:'start'});
}
document.querySelectorAll('.settings-jumps a').forEach(link => link.addEventListener('click', () => {
  const target = document.getElementById(link.hash.slice(1));
  if (target) revealEditor(target);
}));
addEventListener('hashchange', revealHash);
revealHash();

const permissionGroups = [...document.querySelectorAll('.permission-group')];
function countPermissions() {
  permissionGroups.forEach(group => {
    let count = group.querySelector('.disclosure-count');
    if (!count) {
      count = document.createElement('span');
      count.className = 'disclosure-count';
      group.querySelector('summary').append(count);
    }
    count.textContent = `${group.querySelectorAll('input:checked').length} enabled`;
  });
}
permissionGroups.forEach(group => group.addEventListener('change', countPermissions));
document.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', countPermissions));
countPermissions();

// Row IDs are stable after saving. New controls use unique indexes until then.
let setupIndex = 1000;
document.addEventListener('click', event => {
  const add = event.target.closest('[data-setup-add]');
  if (add) {
    const kind = add.dataset.setupAdd;
    const template = document.getElementById(`${kind}-template`);
    const rows = document.getElementById(`${kind}-rows`);
    if (!template || !rows) return;
    const container = document.createElement('div');
    container.innerHTML = template.innerHTML.replaceAll('INDEX', String(setupIndex++));
    rows.append(...container.childNodes);
    rows.lastElementChild?.querySelector('[data-setup-label]')?.focus();
    return;
  }
  const remove = event.target.closest('[data-setup-remove]');
  if (remove) { remove.closest('.setup-row').remove(); return; }
  const move = event.target.closest('[data-setup-move]');
  if (!move) return;
  const row = move.closest('.setup-row');
  if (move.dataset.setupMove === 'up' && row.previousElementSibling) row.previousElementSibling.before(row);
  if (move.dataset.setupMove === 'down' && row.nextElementSibling) row.nextElementSibling.after(row);
  move.focus();
});
document.addEventListener('input', event => {
  if (event.target.matches('[data-setup-label]')) {
    event.target.closest('.setup-row').querySelector('summary').textContent = event.target.value || 'New field';
  }
});
