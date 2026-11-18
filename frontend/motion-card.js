// Anazori's violet, pearl and amethyst identity, on a gently turning keepsake.
export const CARD_DURATION = 12000;
export const CARD_WIDTH = 1280;
export const CARD_HEIGHT = 720;
const TAU = Math.PI * 2;
const textures = new WeakMap();
const logos = new Map(), logoLoads = new Map();
const WORDMARK = '/assets/2026/anazori-main-font.png';
const DISPLAY = '"Satoshi", Arial';
const C = { ink: '#30213f', cream: '#f3ecfa', pearl: '#ede2ff', lilac: '#c4a0ef', violet: '#9666cd' };
async function loadArtwork(source) {
    if (typeof Image === 'function') { const image = new Image(); image.crossOrigin = 'anonymous'; image.src = source; await image.decode(); return image; }
    const response = await fetch(source); if (!response.ok) throw new Error('Artwork unavailable');
    return createImageBitmap(await response.blob());
}
function createSurface(ctx, width, height) {
    const canvas = ctx.canvas.ownerDocument ? ctx.canvas.ownerDocument.createElement('canvas') : new OffscreenCanvas(width, height);
    canvas.width = width; canvas.height = height; return canvas;
}
export async function prepareMotionCard(data) {
    const url = data.logo || '/assets/logo.png';
    if (!logoLoads.has(url)) logoLoads.set(url, (async () => {
        for (const source of [...new Set([url, '/assets/logo.png'])]) {
            try { logos.set(url, await loadArtwork(source)); return; } catch { }
        }
    })());
    await logoLoads.get(url);
    if (!logoLoads.has(WORDMARK)) logoLoads.set(WORDMARK, (async () => {
        try { logos.set(WORDMARK, await loadArtwork(WORDMARK)); } catch { }
    })());
    await logoLoads.get(WORDMARK);
}
function text(ctx, value, x, y, size, color = C.cream, family = DISPLAY, weight = 400) { ctx.fillStyle = color; ctx.font = `${weight} ${size}px ${family}`; ctx.fillText(String(value), x, y); }
function fitLine(ctx, value, x, y, maxWidth, size, color = C.cream, family = DISPLAY, weight = 400) { ctx.font = `${weight} ${size}px ${family}`; while (ctx.measureText(String(value)).width > maxWidth && size > 10) { size--; ctx.font = `${weight} ${size}px ${family}`; } ctx.fillStyle = color; ctx.fillText(String(value), x, y, maxWidth); }
export function fitName(ctx, name, maxWidth = 595) {
    const value = String(name || 'Your name').trim(); let size = 46, lines = [];
    do { ctx.font = `600 ${size}px ${DISPLAY}`; lines = []; let line = ''; for (const word of value.split(/\s+/)) { if (line && ctx.measureText(line + ' ' + word).width > maxWidth) { lines.push(line); line = word; } else line = line ? line + ' ' + word : word; } if (line) lines.push(line); if (lines.length <= 2 && lines.every(line => ctx.measureText(line).width <= maxWidth)) break; size--; } while (size > 17);
    return { lines: lines.length <= 2 ? lines : [value], size };
}
function ticketPath(ctx) {
    // An asymmetric die-cut festival badge: chamfered paper, a stepped crest,
    // and an angled outer wing. It has no tear-off stub or admission perforation.
    ctx.beginPath(); ctx.moveTo(-451, -248); ctx.lineTo(111, -248); ctx.quadraticCurveTo(124, -248, 134, -237); ctx.lineTo(154, -216); ctx.lineTo(208, -216); ctx.lineTo(236, -248); ctx.lineTo(445, -248); ctx.quadraticCurveTo(467, -248, 478, -225); ctx.lineTo(516, -147); ctx.lineTo(516, 153); ctx.lineTo(460, 233); ctx.quadraticCurveTo(450, 248, 429, 248); ctx.lineTo(-456, 248); ctx.lineTo(-508, 196); ctx.lineTo(-508, -185); ctx.closePath();
}
function spectrum(ctx, x1, y1, x2, y2) { const fill = ctx.createLinearGradient(x1, y1, x2, y2); fill.addColorStop(0, C.pearl); fill.addColorStop(.54, C.lilac); fill.addColorStop(1, C.violet); return fill; }
function officialLogo(ctx, data, x, y, size = 70) {
    const img = logos.get(data.logo || '/assets/logo.png'); if (!img) return;
    const height = size * (img.naturalHeight ?? img.height) / (img.naturalWidth ?? img.width);
    ctx.drawImage(img, x, y, size, height);
}
function frequency(ctx, phase) {
    for (let row = 0; row < 5; row++)for (let i = 0; i < 46; i++) {
        const x = -500 + i * 15, y = 6 + Math.sin(i * .19 + phase + row * .23) * (23 + row * 4) + row * 4;
        const r = 1.5 + Math.sin(i * .3 + phase) * .5;
        ctx.fillStyle = row % 3 === 0 ? C.pearl : row % 3 === 1 ? C.lilac : C.violet;
        ctx.globalAlpha = .18 + .28 * (r / 2); ctx.beginPath(); ctx.arc(x, y, r, 0, TAU); ctx.fill();
    }
    ctx.globalAlpha = 1;
}
function frontRegionPath(ctx, wing = false) {
    // Both materials meet on the same curve; the ticket clip trims their outer edges.
    const edge = wing ? 535 : -535;
    ctx.beginPath(); ctx.moveTo(213, -260);
    ctx.bezierCurveTo(169, -89, 273, 69, 203, 260);
    ctx.lineTo(edge, 260); ctx.lineTo(edge, -260); ctx.closePath();
}
// Hosting can resize the square artwork; crop the lettering in proportions.
function drawWordmarkArtwork(ctx, artwork, x, y, width) {
    const imageWidth = artwork.naturalWidth ?? artwork.width, imageHeight = artwork.naturalHeight ?? artwork.height;
    ctx.drawImage(artwork, imageWidth * 336 / 2160, imageHeight * 908 / 2160, imageWidth * 1490 / 2160, imageHeight * 344 / 2160, x, y, width, width * 344 / 1490);
}
function glowingWordmark(ctx, value, phase) {
    const artwork = logos.get(WORDMARK);
    if (artwork) {
        ctx.save(); ctx.shadowColor = '#d0acf8b3'; ctx.shadowBlur = 22 + Math.sin(phase) * 3;
        drawWordmarkArtwork(ctx, artwork, -455, -184, 580);
        ctx.shadowBlur = 0; drawWordmarkArtwork(ctx, artwork, -455, -184, 580); ctx.restore(); return;
    }
    ctx.save(); ctx.font = `400 72px ${DISPLAY}`;
    ctx.fillStyle = spectrum(ctx, -453, -120, 125, -80);
    ctx.shadowColor = '#b4f5e6b3'; ctx.shadowBlur = 22 + Math.sin(phase) * 3;
    ctx.fillText(value, -455, -101, 599);
    ctx.shadowColor = '#d1b8f7a6'; ctx.shadowBlur = 8;
    ctx.fillText(value, -455, -101, 599);
    ctx.shadowBlur = 0; ctx.fillText(value, -455, -101, 599); ctx.restore();
}
function paintFace(ctx, data, phase, back, staticOnly = false) {
    ctx.clearRect(0, 0, 1080, 560); ctx.save(); ctx.translate(540, 280); ticketPath(ctx); ctx.save(); ctx.clip();
    const base = ctx.createLinearGradient(-508, -248, 508, 248); base.addColorStop(0, '#302044'); base.addColorStop(.6, '#1a1428'); base.addColorStop(1, '#100e1a'); ctx.fillStyle = base; ctx.fillRect(-510, -250, 1048, 500);
    if (!back) {
        const wing = ctx.createLinearGradient(190, -248, 508, 248); wing.addColorStop(0, '#dfcef4'); wing.addColorStop(.55, '#c4a3e8'); wing.addColorStop(1, '#af8bdb'); ctx.fillStyle = wing;
        frontRegionPath(ctx, true); ctx.fill();
        ctx.save(); frontRegionPath(ctx); ctx.clip();
        const pearl = ctx.createLinearGradient(-508, 68, 200, 248); pearl.addColorStop(0, '#fcf8ff'); pearl.addColorStop(1, '#e9ddf6'); ctx.fillStyle = pearl; ctx.fillRect(-510, 68, 1048, 192);
        ctx.fillStyle = spectrum(ctx, -508, 67, 220, 67); ctx.fillRect(-510, 67, 1048, 3);
        fitLine(ctx, 'CCSA / DIBRUGARH UNIVERSITY', -452, -200, 589, 14, C.pearl, DISPLAY, 500);
        if (!staticOnly) glowingWordmark(ctx, String(data.festival || 'ANAZORI').toUpperCase(), phase);
        fitLine(ctx, data.date || 'Dates dropping soon', -451, -28, 575, 18, C.cream, DISPLAY, 500);
        if (!staticOnly) frequency(ctx, phase);
        const name = fitName(ctx, data.name), y = name.lines.length === 1 ? 149 : 123;
        name.lines.forEach((line, index) => fitLine(ctx, line, -451, y + index * name.size * 1.2, 595, name.size, C.ink, DISPLAY, 600));
        fitLine(ctx, data.notice || 'Keepsake only · Not valid for event entry', -451, 213, 610, 15, '#695478', DISPLAY, 500);
        ctx.restore();
        officialLogo(ctx, data, 389, -210, 64);
        fitLine(ctx, String(data.edition || 'V16.0').toUpperCase(), 260, 35, 214, 66, C.ink, DISPLAY, 500);
    } else {
        ctx.fillStyle = spectrum(ctx, -508, -248, 508, 248); ctx.fillRect(-510, -250, 1048, 500);
        ctx.save(); ctx.globalAlpha = .1; ctx.strokeStyle = C.ink; ctx.lineWidth = 1; for (let i = 0; i < 16; i++) { ctx.beginPath(); ctx.moveTo(210 + i * 29, -250); ctx.lineTo(-150 + i * 29, 250); ctx.stroke(); } ctx.restore();
        const artwork = logos.get(WORDMARK);
        if (artwork) drawWordmarkArtwork(ctx, artwork, -451, -216, 430);
        else fitLine(ctx, String(data.festival || 'ANAZORI').toUpperCase(), -451, -162, 680, 43, C.ink);
        officialLogo(ctx, data, 385, -205, 64);
        const edition = String(data.edition || 'V16.0').toUpperCase(); ctx.font = `500 138px ${DISPLAY}`; ctx.strokeStyle = C.ink; ctx.lineWidth = 1.7; ctx.strokeText(edition, -455, 32, 870);
        fitLine(ctx, data.name || 'Your name', -451, 139, 840, 38, C.ink, DISPLAY, 600);
        fitLine(ctx, data.notice || 'Keepsake only · Not valid for event entry', -451, 214, 780, 15, C.ink, DISPLAY, 500);
        text(ctx, String(data.year || ''), 352, 210, 17, C.ink);
    }
    // A soft moving foil highlight is part of the material, not a text overlay.
    if (!staticOnly) paintFoil(ctx, phase);
    ctx.restore(); if (!staticOnly) { ticketPath(ctx); ctx.strokeStyle = back ? '#fcf8ff99' : '#cfb5e9bb'; ctx.lineWidth = 1.5; ctx.stroke(); } ctx.restore();
}
function paintFoil(ctx, phase) {
    const shine = ctx.createLinearGradient(-600 + Math.sin(phase) * 600, -250, 100 + Math.sin(phase) * 600, 250); shine.addColorStop(0, '#ffffff00'); shine.addColorStop(.5, '#ffffff10'); shine.addColorStop(1, '#ffffff00'); ctx.fillStyle = shine; ctx.fillRect(-510, -250, 1048, 500);
}
function paintCachedFace(surface, data, phase, back) {
    // Fonts, typography, logos and materials change only when the ticket data
    // changes. Retain both faces; waveform, glow and foil still advance every frame.
    const key = JSON.stringify([data.name, data.festival, data.logo, data.edition, data.year, data.date, data.notice]);
    if (surface.faceKey !== key) { surface.faceKey = key; surface.faces = []; }
    const side = back ? 1 : 0;
    if (!surface.faces[side]) {
        const canvas = createSurface(surface.ctx, 1080, 560);
        paintFace(canvas.getContext('2d'), data, phase, back, true);
        surface.faces[side] = canvas;
    }
    const ctx = surface.ctx;
    ctx.clearRect(0, 0, 1080, 560); ctx.drawImage(surface.faces[side], 0, 0);
    ctx.save(); ctx.translate(540, 280); ticketPath(ctx); ctx.clip();
    if (!back) {
        ctx.save(); frontRegionPath(ctx); ctx.clip();
        glowingWordmark(ctx, String(data.festival || 'ANAZORI').toUpperCase(), phase);
        frequency(ctx, phase); ctx.restore();
    }
    paintFoil(ctx, phase); ctx.restore();
    // Keep the original edge above the moving foil, including translucent pixels.
    ctx.save(); ctx.translate(540, 280); ticketPath(ctx); ctx.strokeStyle = back ? '#fcf8ff99' : '#cfb5e9bb'; ctx.lineWidth = 1.5; ctx.stroke(); ctx.restore();
}
const smooth = t => t * t * (3 - 2 * t);
function movement(time) {
    const t = (time % CARD_DURATION) / 1000, phase = t / CARD_DURATION * 1000 * TAU;
    let yaw;
    if (t < 3.5) yaw = .15 * Math.sin(t / 3.5 * Math.PI);
    else if (t < 5.5) yaw = smooth((t - 3.5) / 2) * Math.PI;
    else if (t < 7.5) yaw = Math.PI + .13 * Math.sin((t - 5.5) / 2 * Math.PI);
    else if (t < 9.7) yaw = Math.PI + smooth((t - 7.5) / 2.2) * Math.PI;
    else yaw = TAU + .14 * Math.sin((t - 9.7) / 2.3 * Math.PI);
    const pitch = .07 + .08 * Math.sin(phase), roll = -.028 + .045 * Math.sin(phase);
    return { yaw, pitch, roll, phase, cy: Math.cos(yaw), sy: Math.sin(yaw), cp: Math.cos(pitch), sp: Math.sin(pitch), cr: Math.cos(roll), sr: Math.sin(roll) };
}
function project(x, y, m, back, result = {}) {
    if (back) x = -x;
    const rx = x * m.cy, rz = -x * m.sy, ry = y * m.cp - rz * m.sp, depth = y * m.sp + rz * m.cp;
    const perspective = 1700 / (1700 - depth), xx = rx * perspective, yy = ry * perspective;
    result.x = 640 + xx * m.cr - yy * m.sr;
    result.y = 355 + Math.sin(m.phase) * 6 + xx * m.sr + yy * m.cr;
    return result;
}
function clipProjectedTicket(ctx, m, back) {
    const point = (x, y) => project(x, y, m, back);
    ticketPath({
        beginPath: () => ctx.beginPath(), closePath: () => ctx.closePath(),
        moveTo: (x, y) => { const p = point(x, y); ctx.moveTo(p.x, p.y); },
        lineTo: (x, y) => { const p = point(x, y); ctx.lineTo(p.x, p.y); },
        quadraticCurveTo: (cx, cy, x, y) => { const c = point(cx, cy), p = point(x, y); ctx.quadraticCurveTo(c.x, c.y, p.x, p.y); }
    });
    ctx.clip();
}
function triangle(ctx, image, s0, s1, s2, d0, d1, d2) {
    const u1 = s1.x - s0.x, v1 = s1.y - s0.y, u2 = s2.x - s0.x, v2 = s2.y - s0.y, det = u1 * v2 - u2 * v1;
    if (Math.abs(det) < .0001) return;
    const a = ((d1.x - d0.x) * v2 - (d2.x - d0.x) * v1) / det, b = ((d1.y - d0.y) * v2 - (d2.y - d0.y) * v1) / det;
    const c = (u1 * (d2.x - d0.x) - u2 * (d1.x - d0.x)) / det, d = (u1 * (d2.y - d0.y) - u2 * (d1.y - d0.y)) / det;
    const cx = (d0.x + d1.x + d2.x) / 3, cy = (d0.y + d1.y + d2.y) / 3;
    ctx.save(); ctx.beginPath();
    ctx.moveTo(d0.x + (d0.x - cx) * .035, d0.y + (d0.y - cy) * .035);
    ctx.lineTo(d1.x + (d1.x - cx) * .035, d1.y + (d1.y - cy) * .035);
    ctx.lineTo(d2.x + (d2.x - cx) * .035, d2.y + (d2.y - cy) * .035);
    ctx.closePath(); ctx.clip(); ctx.transform(a, b, c, d, d0.x - a * s0.x - c * s0.y, d0.y - b * s0.x - d * s0.y); ctx.drawImage(image, 0, 0); ctx.restore();
}
function paintBackdrop(ctx) {
    const background = ctx.createLinearGradient(140, -140, 1140, 860); background.addColorStop(0, '#181020'); background.addColorStop(.48, '#090910'); background.addColorStop(1, '#140d21'); ctx.fillStyle = background; ctx.fillRect(0, 0, 1280, 720);
    function glow(x, y, stops) {
        ctx.save(); ctx.translate(x, y); ctx.scale(1280 * Math.SQRT2, 720 * Math.SQRT2);
        const fill = ctx.createRadialGradient(0, 0, 0, 0, 0, 1); stops.forEach(([offset, color]) => fill.addColorStop(offset, color));
        ctx.fillStyle = fill; ctx.fillRect(-1, -1, 2, 2); ctx.restore();
    }
    glow(1280, 720, [[0,'rgba(239,226,255,.30)'],[.2,'rgba(145,78,222,.25)'],[.49,'rgba(145,78,222,0)'],[1,'rgba(145,78,222,0)']]);
    glow(0, 0, [[0,'rgba(255,255,255,.78)'],[.13,'rgba(214,191,255,.42)'],[.3,'rgba(139,76,224,.24)'],[.53,'rgba(139,76,224,0)'],[1,'rgba(139,76,224,0)']]);
    ctx.strokeStyle = '#ede2ff12'; ctx.lineWidth = 1; for (let i = 0; i < 4; i++) { ctx.beginPath(); ctx.ellipse(640, 395, 550 + i * 42, 185 + i * 40, -.14, 0, TAU); ctx.stroke(); }
    // Grounding shadow remains below the ticket as it turns through real perspective.
    ctx.save(); ctx.translate(640, 620); ctx.scale(1, .12); const shadow = ctx.createRadialGradient(0, 0, 30, 0, 0, 470); shadow.addColorStop(0, '#06091470'); shadow.addColorStop(1, '#06091400'); ctx.fillStyle = shadow; ctx.fillRect(-480, -480, 960, 960); ctx.restore();
}
function prepareMesh(surface, columns, rows) {
    if (surface.mesh?.columns === columns) return surface.mesh;
    const source = [], projected = [];
    for (let row = 0; row <= rows; row++)for (let col = 0; col <= columns; col++) {
        source.push({x: col / columns * 1080, y: row / rows * 560});
        projected.push({x: 0, y: 0});
    }
    return surface.mesh = {columns, source, projected};
}
export function drawMotionCard(ctx, data, time = 0) {
    const m = movement(time), back = m.cy < 0;
    let surface = textures.get(ctx);
    if (!surface) { const canvas = createSurface(ctx, 1080, 560); surface = { canvas, ctx: canvas.getContext('2d') }; textures.set(ctx, surface); }
    // The scenery and shadow are static. Cache at the full output resolution;
    // the face, foil, waveform and perspective still render at every animation frame.
    if (!surface.backdrop || surface.backdrop.width !== ctx.canvas.width || surface.backdrop.height !== ctx.canvas.height) {
        const canvas = createSurface(ctx, ctx.canvas.width, ctx.canvas.height);
        const background = canvas.getContext('2d'); background.scale(canvas.width / CARD_WIDTH, canvas.height / CARD_HEIGHT); paintBackdrop(background); surface.backdrop = canvas;
    }
    paintCachedFace(surface, data, m.phase, back);
    ctx.save(); ctx.scale(ctx.canvas.width / CARD_WIDTH, ctx.canvas.height / CARD_HEIGHT);
    ctx.drawImage(surface.backdrop, 0, 0, CARD_WIDTH, CARD_HEIGHT);
    const columns = ctx.canvas.width > 1280 ? 16 : 12, rows = 3;
    const {source, projected} = prepareMesh(surface, columns, rows);
    for (let i = 0; i < source.length; i++) project(source[i].x - 540, source[i].y - 280, m, back, projected[i]);
    ctx.save(); clipProjectedTicket(ctx, m, back);
    for (let row = 0; row < rows; row++)for (let col = 0; col < columns; col++) {
        const a = row * (columns + 1) + col, b = a + 1, d = a + columns + 1, c = d + 1;
        triangle(ctx, surface.canvas, source[a], source[b], source[c], projected[a], projected[b], projected[c]);
        triangle(ctx, surface.canvas, source[a], source[c], source[d], projected[a], projected[c], projected[d]);
    }
    ctx.restore(); ctx.restore();
}
