<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('ANAZORI_LOCAL_MIGRATE')!=='1')exit('Explicit local migration only.');
$settings=require dirname(__DIR__).'/development/anazori-config.php';
$database=$settings['ANAZORI_LOCAL_DB_NAME']??'anazori_local';
if($database!=='anazori_local')throw new RuntimeException('Local migration only supports the named local database.');
$sourcePath=__DIR__.'/../data/anazori.sqlite';
if(!is_file($sourcePath))throw new RuntimeException('The existing SQLite database is required.');
$source=new PDO('sqlite:'.$sourcePath,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
$target=new PDO('mysql:host=127.0.0.1;dbname='.$database.';charset=utf8mb4',$settings['ANAZORI_LOCAL_DB_USER'],$settings['ANAZORI_LOCAL_DB_PASS'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
if($target->query('SHOW TABLES')->fetchAll())throw new RuntimeException('The local destination must be empty. No existing database is overwritten.');
$target->exec(file_get_contents(__DIR__.'/../deploy/anazori-hostinger.sql'));
$tables=$source->query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
$target->beginTransaction();$counts=[];
try{
 foreach($tables as $table){
  if(!preg_match('/^[a-z0-9_]+$/D',$table))throw new RuntimeException('Unexpected table name.');
  $target->exec('DELETE FROM `'.$table.'`');$rows=$source->query('SELECT * FROM "'.$table.'"')->fetchAll();
  if($rows){$columns=array_keys($rows[0]);$insert=$target->prepare('INSERT INTO `'.$table.'` (`'.implode('`,`',$columns).'`) VALUES ('.implode(',',array_fill(0,count($columns),'?')).')');foreach($rows as $row)$insert->execute(array_values($row));}
  $count=(int)$target->query('SELECT COUNT(*) FROM `'.$table.'`')->fetchColumn();if($count!==count($rows))throw new RuntimeException('Row reconciliation failed: '.$table);$counts[$table]=$count;
 }
 $target->commit();
}catch(Throwable $error){if($target->inTransaction())$target->rollBack();throw $error;}
echo 'PASS '.count($counts)." local tables copied and reconciled. Original SQLite database retained.\n";
