<?php
// Flat source artwork and original SVG illustrations; no scene renderer or model downloads.
function festival_character(string $name, string $class = '', bool $deferred = false): string {
    if (setting('show_characters', '1') !== '1') return '';
    $sizes = ['pikachu'=>[475,475], 'gengar'=>[475,475], 'charizard'=>[475,475], 'minion'=>[415,300], 'stuart'=>[503,600], 'doraemon'=>[600,303], 'sonic'=>[366,600], 'dragon'=>[380,230], 'kirby'=>[529,700], 'link'=>[645,700], 'megaman'=>[675,700], 'roz-research'=>[900,506]];
    if (!isset($sizes[$name])) return '';
    // Both Minion artworks depict Stuart, so share the same appearance budget.
    static $appearances=[];
    $identity=$name==='minion'?'stuart':$name;
    if (($appearances[$identity]??0)>=2) return '';
    $appearances[$identity]=($appearances[$identity]??0)+1;
    [$width,$height] = $sizes[$name];
    $src = setting('character_'.$name, '') ?: '/assets/2026/characters/'.$name.($name==='dragon'?'.svg':'.webp');
    return '<img class="festival-character character-'.e($name).' '.e($class).'" '.($deferred?'data-character-src':'src').'="'.e($src).'" width="'.$width.'" height="'.$height.'" alt="" aria-hidden="true" loading="lazy" decoding="async">';
}
function festival_scene_character(string $slug, array $event): string {
    $cast = ['goc'=>'hackathon-pixel', 'joystick'=>'gaming-duo', 'prativa'=>'stuart', 'workshops'=>'walle-build', 'paper-presentation'=>'baymax-help', 'tulika'=>'dragon', 'treasure-hunt'=>'link','inauguration'=>'ceremony','youth-parliament'=>'parliament','cultural-night'=>'stuart'];
    return $cast[$slug] ?? (['tech'=>'walle-build','culture'=>'coco-guitar','gaming'=>'gaming-duo','sports'=>'sonic'][$event['category']??''] ?? 'dragon');
}
function festival_gaming_art(bool $deferred = false): string {
    if (setting('show_characters','1')!=='1') return '';
    $attribute=$deferred?'data-character-src':'src';
    $mlbb=setting('character_mlbb','')?:'/assets/2026/characters/mlbb-gusion.webp';
    return '<div class="gaming-duo theatre-character"><div class="gaming-mlbb"><img class="gaming-character" '.$attribute.'="'.e($mlbb).'" width="720" height="461" alt="" loading="lazy" decoding="async"><span>Mobile Legends</span></div></div>';
}
function festival_relic_frame(): string {
    return '<span class="relic-corners" aria-hidden="true"><i></i><i></i><i></i><i></i></span>';
}
function festival_sprite(string $name, string $class = ''): string {
    if(setting('show_characters','1')!=='1' || !in_array($name,['doraemon-run','pikachu-run','coco-guitar'],true)) return '';
    $base='/assets/2026/animations/'.$name;
    $poster=$base.'-poster.webp?v=2026.39';
    return '<span class="animation-sprite sprite-'.e($name).' '.e($class).'" data-sprite-identity="'.e($name).'" aria-hidden="true"><img class="sprite-poster" src="'.$poster.'" width="160" height="160" alt="" loading="lazy" decoding="async"><img class="sprite-sheet" src="'.$poster.'" data-sprite-src="'.$base.'.webp" width="160" height="160" alt="" loading="lazy" decoding="async"></span>';
}
function festival_performance(string $name, string $class = '', string $play = 'loop'): string {
    $durations=['walle-build'=>5,'coco-guitar'=>5.005,'stitch-light'=>2.884,'totoro-visit'=>1.017,'baymax-help'=>.68,'among-us'=>.92,'mario-discovery'=>.32,'deadpool-photo'=>1.334,'pikachu-run'=>.404,'roz-code'=>4,'festival-snow'=>10.01,'dinosaur-run'=>1.55];
    if(setting('show_characters','1')!=='1' || !isset($durations[$name])) return '';
    $base='/assets/2026/vector/'.$name;
    return '<span class="content-performance performance-'.e($name).' '.e($class).'" data-performance="'.e($name).'" data-performance-play="'.e($play).'" data-performance-duration="'.$durations[$name].'" aria-hidden="true"><img src="'.$base.'-still.svg?v=2026.46" data-performance-src="'.$base.'-motion.svg?v=2026.46" width="480" height="480" alt="" loading="lazy" decoding="async"></span>';
}
function festival_vector_character(string $name, string $class = ''): string {
    if(setting('show_characters','1')!=='1' || !in_array($name,['roz-code','kirby','link'],true)) return '';
    $file=$name==='roz-code'?'roz-code-still':$name;
    return '<img class="festival-character vector-character character-'.e($name).' '.e($class).'" src="/assets/2026/vector/'.$file.'.svg?v=2026.43" width="520" height="640" alt="" aria-hidden="true" loading="lazy" decoding="async">';
}
