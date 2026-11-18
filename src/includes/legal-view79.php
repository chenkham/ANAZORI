<?php
function az_legal_page79(string $kind): void {
    $title=$kind==='privacy'?'Privacy policy':'Terms of participation';
    echo '<section class="page-intro section-pad legal-intro"><h1>'.e($title).'</h1><p>ANAZORI · '.e(setting('year')).'</p></section><section class="legal-content section-pad">';
    foreach(preg_split('/\R\s*\R/',setting($kind.'_content')) as $paragraph){
        $lines=preg_split('/\R/',trim($paragraph));if(!$lines||$lines[0]==='')continue;
        if(str_starts_with($lines[0],'## '))echo '<h2>'.e(substr(array_shift($lines),3)).'</h2>';
        if($lines)echo '<p>'.nl2br(e(implode("\n",$lines))).'</p>';
    }
    echo '<p>Contact the organising team: <a href="mailto:'.e(setting('email')).'">'.e(setting('email')).'</a>.</p></section>';
}
