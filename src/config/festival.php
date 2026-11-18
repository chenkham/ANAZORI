<?php
// The supplied V16.0 brochure is the initial programme; Studio edits remain authoritative.
$brochure=require __DIR__.'/brochure-v16.php';
$events=$brochure['events'];foreach($events as &$event)unset($event['page']);unset($event);
return ['year'=>2026,'theme'=>'Culture × Tech','dates'=>'Dates to be announced','events'=>$events];
