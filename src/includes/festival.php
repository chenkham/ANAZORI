<?php
require_once __DIR__.'/../config/security.php';
require_once __DIR__.'/cms.php';
require_once __DIR__.'/festival-scenes.php';
require_once __DIR__.'/intro-video.php';
$festival=['year'=>setting('year'),'theme'=>setting('tagline'),'events'=>[]];
function festival_version(): string { return preg_replace('/^V(\d+)$/i','V$1.0',setting('version')); }
/** Keep public archive captions edition-neutral without changing the saved records. */
function festival_memory_label(string $label): string {
 $label=preg_replace('/\b(?:2024|v14(?:\.0)?)\b/iu','',$label)??$label;
 return trim(preg_replace('/\s+/u',' ',$label)??$label);
}
foreach(cms_records('event') as $record){$festival['events'][$record['slug']]=array_replace($record['fields'],['title'=>$record['title'],'cms_id'=>$record['id']]);}
function arrow_icon(string $direction='up'): string {
 $path=$direction==='right'?'m9 6 6 6-6 6':match($GLOBALS['activePage']??'home'){
  'events'=>'M4 5h16v5a2 2 0 0 0 0 4v5H4v-5a2 2 0 0 0 0-4ZM9 8v8',
  'gallery'=>'M9 4H4v5m11-5h5v5M4 15v5h5m6 0h5v-5',
  'teams'=>'M9 8a3 3 0 1 0-6 0 3 3 0 0 0 6 0Zm12 8a3 3 0 1 0-6 0 3 3 0 0 0 6 0ZM8 10l8 4',
  'account'=>'m6 12 4 4 8-8',default=>'M8 5v14l11-7Z',
 };
 return '<svg class="action-emblem" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="'.$path.'"/></svg>';
}
function weave_mark(): string {
 return '<svg viewBox="0 0 100 100" fill="none" aria-hidden="true"><path d="M15 15 85 85M15 85 85 15M30 5 95 70M5 30 70 95M5 70 70 5M30 95 95 30" stroke="currentColor" stroke-width="8"/></svg>';
}
/** Shared transparent character artwork for programme previews and event pages. */
function festival_event_character(string $art,string $class='',bool $deferred=false): string {
 $attribute=$deferred?'data-character-src':'src';$svgAttribute=$deferred?'data-character-href':'href';
 $class=e(trim($class.' programme-character-art programme-character--'.($art==='ceremony'?'genie':'phoenix')));
 if($art==='ceremony')return '<img class="'.$class.'" '.$attribute.'="/assets/2026/graphics/genie-inauguration77.png"'.($deferred?'':az_image_attributes84('/assets/2026/graphics/genie-inauguration77.png','(max-width:700px) 80vw, 45vw')).' alt="" width="1257" height="1475" loading="lazy" decoding="async">';
 // The viewport trims transparent margins while keeping the original edited PNG intact.
 return '<svg class="'.$class.'" viewBox="287 2 867 1075" width="867" height="1075" preserveAspectRatio="xMidYMax meet" aria-hidden="true" focusable="false"><image '.$svgAttribute.'="/assets/2026/graphics/phoenix-microphone77.png" width="1447" height="1087"/></svg>';
}
function festival_programme_companion(string $slug,array $event,bool $deferred=true): string {
 $cast=festival_scene_character($slug,$event);
 if($slug==='treasure-hunt'){ob_start();require __DIR__.'/treasure-scene.php';return ob_get_clean();}
 if(in_array($cast,['ceremony','parliament'],true))return festival_event_character($cast,'theatre-character programme-emblem',$deferred);
 if(in_array($cast,['performance','hackathon-pixel'],true))return '<img class="theatre-character programme-emblem" src="/assets/2026/graphics/'.e($cast).'.svg" alt="" width="520" height="640" loading="lazy">';
 if($cast==='gaming-duo')return festival_gaming_art($deferred);
 if(in_array($cast,['walle-build','coco-guitar','baymax-help','roz-code'],true))return festival_performance($cast,'theatre-character');
 return $cast==='link'?festival_vector_character('link','theatre-character'):festival_character($cast,'theatre-character',$deferred);
}
function event_art(array $event): string {
 if(!empty($event['image']))return '<img class="event-cover" src="'.e($event['image']).'"'.az_image_attributes84($event['image'],'(max-width:700px) calc(100vw - 64px), 40vw').' alt="'.e($event['title']??'Event artwork').'" loading="lazy" decoding="async" width="1200" height="800">';
 return '<div class="event-programme-art" aria-hidden="true">'.festival_programme_companion($event['_event_slug']??'',$event,false).'</div>';
}
function event_card(string $slug,array $event,int $index): void { ?>
<article class="event-card" data-category="<?= e($event['category']) ?>" data-title="<?= e(strtolower($event['title'].' '.$event['format'])) ?>">
<?= festival_relic_frame() ?><a class="event-card-link" href="/event.php?name=<?= e($slug) ?>"><div class="event-art art-<?= e($event['art']) ?> color-<?= e($event['color']) ?>"><?= event_art($event) ?><span class="card-arrow"><?= arrow_icon() ?></span></div><div class="event-card-body"><h3><?= e($event['title']) ?></h3><p><?= e($event['short']) ?></p><div class="event-card-foot"><span><?= e(cms_phase_label($event)) ?></span><span>Discover <?= arrow_icon('right') ?></span></div></div></a>
</article>
<?php }
