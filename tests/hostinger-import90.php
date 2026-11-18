<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit;
require_once __DIR__.'/../src/includes/commerce.php';
$db=cms_db();
if(APP_ENV!=='development'||DB_DRIVER!=='mysql'||!in_array(DB_HOST,['localhost','127.0.0.1','::1'],true))throw new RuntimeException('Use the local MySQL preparation database.');
$sql=file_get_contents(__DIR__.'/../deploy/anazori-hostinger.sql');
if(preg_match('/^\s*(?:DROP|USE|CREATE DATABASE|GRANT)\b/im',$sql))throw new RuntimeException('The clean seed contains destructive or server-specific SQL.');
$manifest=json_decode(file_get_contents(__DIR__.'/../deploy/database-manifest90.json'),true,512,JSON_THROW_ON_ERROR);
$tables=array_keys($manifest['tables']);
$prefix='qa90_'.bin2hex(random_bytes(6)).'_';$created=[];$checks=0;
// Rename identifier tokens only, preserving text/JSON containing SQL-like content.
$isolated='';$quote=null;$length=strlen($sql);
for($i=0;$i<$length;$i++){
    $char=$sql[$i];
    if($quote!==null){
        $isolated.=$char;
        if($char==='\\'&&$i+1<$length){$isolated.=$sql[++$i];continue;}
        if($char===$quote){if($i+1<$length&&$sql[$i+1]===$quote)$isolated.=$sql[++$i];else $quote=null;}
        continue;
    }
    if($char==="'"||$char==='"'){$quote=$char;$isolated.=$char;continue;}
    if($char==='`'){$end=strpos($sql,'`',$i+1);if($end===false)throw new RuntimeException('Unclosed SQL identifier.');$name=substr($sql,$i+1,$end-$i-1);$isolated.='`'.(in_array($name,$tables,true)?$prefix.$name:$name).'`';$i=$end;continue;}
    $isolated.=$char;
}
try{
    foreach($tables as $table){$name=$prefix.$table;if(!preg_match('/^qa90_[a-f0-9]{12}_[a-z0-9_]+$/D',$name))throw new RuntimeException('Unsafe isolated table name.');$created[]=$name;}
    $db->exec($isolated);
    foreach($tables as $table){$actual=(int)$db->query('SELECT COUNT(*) FROM `'.$prefix.$table.'`')->fetchColumn();if($actual!==$manifest['tables'][$table])throw new RuntimeException('Import row count mismatch: '.$table);$checks++;}
    foreach(['users','cms_content','cms_media','events','st_event_assignments','st_budgets','st_expenses','st_finance_evidence','st_finance_ledger'] as $table){
        $original=$db->query('SELECT * FROM `'.$table.'`')->fetchAll();$copy=$db->query('SELECT * FROM `'.$prefix.$table.'`')->fetchAll();
        if(json_encode($original)!==json_encode($copy))throw new RuntimeException('Import changed preserved values: '.$table);$checks++;
    }
    foreach(['az_participants','az_orders','az_tickets','az_registration_files','az_checkout_drafts','az_mail_jobs89','submissions'] as $table){if((int)$db->query('SELECT COUNT(*) FROM `'.$table.'`')->fetchColumn()!==0)throw new RuntimeException('Participant data remains in '.$table);$checks++;}
    echo 'PASS '.$checks.' MySQL import, preserved-data and participant-reset checks across '.count($tables)." isolated tables.\n";
}finally{
    // Delete only nonce-prefixed QA tables, never existing website tables or a database.
    foreach(array_reverse($created) as $name)$db->exec('DROP TABLE IF EXISTS `'.$name.'`');
}
