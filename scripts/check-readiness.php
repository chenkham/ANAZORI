<?php
if(PHP_SAPI!=='cli')exit;
require __DIR__.'/../src/includes/launch-readiness.php';
$missing=0;
foreach(az_launch_checks() as [$label,$ok,$detail]){echo ($ok?'OK ':'ACTION ').$label.' — '.$detail."\n";if(!$ok)$missing++;}
echo $missing?"$missing configuration items need attention.\n":"Server configuration checks passed. Complete real Google and email tests before launch.\n";
exit($missing?1:0);
