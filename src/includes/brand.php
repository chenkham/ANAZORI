<?php
declare(strict_types=1);

/** Display the supplied artwork without substituting or reconstructing its lettering. */
function anazori_wordmark(string $class = '',string $sizes='145vw'): string {
    return '<span class="anazori-wordmark '.e($class).'" role="img" aria-label="ANAZORI V16.0"><img src="/assets/2026/anazori-main-font.png"'.az_image_attributes84('/assets/2026/anazori-main-font.png',$sizes).' width="2160" height="2160" alt="" decoding="async"></span>';
}
