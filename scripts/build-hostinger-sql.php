<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli')exit('Use the command line.');
require_once __DIR__.'/../src/includes/commerce.php';
$db=cms_db();
$sqlite=$db->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite';
if(!$sqlite&&$db->getAttribute(PDO::ATTR_DRIVER_NAME)!=='mysql')throw new RuntimeException('Build the clean deployment seed from SQLite or MySQL.');
if(!$sqlite){
    require_once __DIR__.'/database-export90.php';
    $path=__DIR__.'/../deploy/anazori-hostinger.sql';
    $temporary=$path.'.'.bin2hex(random_bytes(6)).'.tmp';
    $keep=['users','st_event_assignments','cms_content','cms_media','events','st_budgets','st_expenses','st_finance_evidence','st_finance_ledger'];
    $counts=az_mysql_export90($db,$temporary,static function(string $table)use($db,$keep):iterable {
        if($table==='cms_settings')return $db->query("SELECT * FROM cms_settings WHERE setting_key<>'integrations_private' AND setting_key<>'mail_worker_heartbeat89' AND setting_key NOT LIKE 'phonepe_token%' ORDER BY setting_key");
        if($table==='visitors')return [['id'=>1,'count'=>0,'updated_at'=>gmdate('Y-m-d H:i:s')]];
        return in_array($table,$keep,true)?$db->query('SELECT * FROM `'.$table.'`'):[];
    },'Clean hosting installation: staff access, content and forms preserved; participant accounts and their operational data excluded');
    if(!rename($temporary,$path))throw new RuntimeException('Could not publish the clean SQL export.');
    file_put_contents(__DIR__.'/../deploy/database-manifest90.json',json_encode(['built_at'=>gmdate('c'),'tables'=>$counts,'participant_accounts'=>0,'staff_accounts'=>$counts['users'],'private_credentials_in_sql'=>false],JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR));
    echo count($counts).' tables exported; '.$counts['users']." staff accounts preserved; no participant records or integration credentials.\n";
    exit;
}
$quote=fn($value)=>$value===null?'NULL':((string)$value===''?"''":"CONVERT(0x".bin2hex((string)$value)." USING utf8mb4)");
$sql="-- Anazori: clean MariaDB/MySQL installation for anazori.ccsdu.in\n-- Import into a NEW EMPTY Hostinger database. No participant, payment, staff or test records.\nSET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n";
$tables=$sqlite?$db->query("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")->fetchAll():array_map(static function(string $name)use($db):array {
    $create=$db->query('SHOW CREATE TABLE `'.str_replace('`','``',$name).'`')->fetch(PDO::FETCH_NUM);
    return ['name'=>$name,'sql'=>preg_replace('/ AUTO_INCREMENT=\d+/','',$create[1])];
},$db->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN));
foreach($tables as $table){
    if(!$sqlite){$sql.=$table['sql'].";\n\n";continue;}
    $name=$table['name'];$columns=$db->query('PRAGMA table_info("'.$name.'")')->fetchAll();$indexes=$db->query('PRAGMA index_list("'.$name.'")')->fetchAll();$keyColumns=[];
    foreach($indexes as $index)foreach($db->query('PRAGMA index_info("'.$index['name'].'")') as $column)$keyColumns[$column['name']]=true;
    $definitions=[];$primary=[];
    foreach($columns as $column){
        $type=strtoupper($column['type']);$auto=$column['pk']&&str_contains($table['sql'],'AUTOINCREMENT');
        if($type==='INTEGER')$type='BIGINT';
        if($type==='TEXT')$type=isset($keyColumns[$column['name']])||$column['pk']?'VARCHAR(255)':'MEDIUMTEXT';
        $definition='`'.$column['name'].'` '.$type;
        if($column['notnull']||$column['pk'])$definition.=' NOT NULL';
        if($auto)$definition.=' AUTO_INCREMENT';
        elseif($column['dflt_value']!==null){$default=$column['dflt_value'];$definition.=' DEFAULT '.(str_contains($type,'TEXT')?'('.$default.')':$default);}
        $definitions[]=$definition;if($column['pk'])$primary[(int)$column['pk']]=$column['name'];
    }
    if($primary){ksort($primary);$definitions[]='PRIMARY KEY (`'.implode('`,`',$primary).'`)';}
    foreach($indexes as $index){
        if($index['origin']==='pk')continue;
        $names=array_column($db->query('PRAGMA index_info("'.$index['name'].'")')->fetchAll(),'name');
        if(!$names)continue;$indexName=str_starts_with($index['name'],'sqlite_autoindex')?'unique_'.implode('_',$names):$index['name'];
        $definitions[]=($index['unique']?'UNIQUE KEY ':'KEY ').'`'.substr($indexName,0,64).'` (`'.implode('`,`',$names).'`)';
    }
    $sql.='CREATE TABLE `'.$name."` (\n  ".implode(",\n  ",$definitions)."\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;\n\n";
}
$insert=function(string $table,array $row)use(&$sql,$quote){$sql.='INSERT INTO `'.$table.'` (`'.implode('`,`',array_keys($row)).'`) VALUES ('.implode(',',array_map($quote,array_values($row))).");\n";};
foreach($db->query('SELECT * FROM cms_content ORDER BY id') as $row){$row['created_by']=0;$insert('cms_content',$row);}
foreach($db->query('SELECT * FROM cms_media ORDER BY id') as $row){$row['uploaded_by']=0;$insert('cms_media',$row);}
foreach($db->query('SELECT * FROM events ORDER BY id') as $row)$insert('events',$row);
// Installation markers for staff permissions are deliberately omitted: first login creates the master account.
foreach($db->query("SELECT * FROM cms_settings WHERE setting_key IN ('site','seeded','settings_revision','programme_release_43','public_data_release_43','launch_forms_52','home_film_location_58','brochure_release_63','official_contact_73')") as $row)$insert('cms_settings',$row);
$insert('visitors',['id'=>1,'count'=>0]);
$sql.="\nSET FOREIGN_KEY_CHECKS=1;\n";
$directory=__DIR__.'/../deploy';if(!is_dir($directory))mkdir($directory,0755,true);
file_put_contents($directory.'/anazori-hostinger.sql',$sql);
echo count($tables)." tables exported with published content. No credentials or operational data included.\n";
