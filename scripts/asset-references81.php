<?php
// Read-only snapshot of asset URLs, including unpublished CMS content and historical tickets.
require_once __DIR__.'/../src/includes/commerce.php';
$db=cms_db();$urls=[];
foreach(['SELECT data AS document FROM cms_content','SELECT value AS document FROM cms_settings','SELECT path AS document FROM cms_media','SELECT snapshot AS document FROM az_orders','SELECT schema_json AS document FROM az_form_responses'] as $sql)foreach($db->query($sql) as $row){
 $text=str_replace('\\/','/',$row['document']);preg_match_all('~/assets/[a-zA-Z0-9_./% -]+~',$text,$matches);foreach($matches[0] as $url)$urls[$url]=true;
}
file_put_contents(__DIR__.'/../output/maintenance81/cms-asset-references.json',json_encode(array_keys($urls),JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));echo count($urls)." CMS and historical asset URLs recorded.\n";
