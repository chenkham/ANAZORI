<?php
declare(strict_types=1);

/** Streaming MySQL backup, with no CLI passwords, shell interpolation or database-name binding. */
function az_mysql_export90(PDO $db,string $path,?callable $rows=null,string $description='Full recovery backup'): array {
    if($db->getAttribute(PDO::ATTR_DRIVER_NAME)!=='mysql')throw new RuntimeException('A MySQL connection is required.');
    $file=fopen($path,'xb');if(!$file)throw new RuntimeException('Could not create a new database export.');
    chmod($path,0600);$counts=[];
    try{
        fwrite($file,'-- ANAZORI: '.$description."\n-- Import into a NEW EMPTY MySQL/MariaDB database selected in phpMyAdmin.\n-- No CREATE DATABASE, USE, DROP, account grants or server-specific definers.\nSET NAMES utf8mb4;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nSET FOREIGN_KEY_CHECKS=0;\n\n");
        $tables=$db->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
        foreach($tables as $table){
            $identifier='`'.str_replace('`','``',$table).'`';
            $create=$db->query('SHOW CREATE TABLE '.$identifier)->fetch(PDO::FETCH_NUM)[1];
            $create=preg_replace('/ AUTO_INCREMENT=\d+/','',$create);
            fwrite($file,$create.";\n\n");
            $records=$rows?$rows($table):$db->query('SELECT * FROM '.$identifier);
            $counts[$table]=0;
            foreach($records as $row){
                $quote=static function($value)use($db):string {if($value===null)return 'NULL';if(is_int($value)||is_float($value))return (string)$value;return $db->quote((string)$value);};
                fwrite($file,'INSERT INTO '.$identifier.' (`'.implode('`,`',array_keys($row)).'`) VALUES ('.implode(',',array_map($quote,array_values($row))).");\n");
                $counts[$table]++;
            }
            fwrite($file,"\n");
        }
        fwrite($file,"SET FOREIGN_KEY_CHECKS=1;\n");
    }catch(Throwable $error){fclose($file);unlink($path);throw $error;}
    fclose($file);return $counts;
}
