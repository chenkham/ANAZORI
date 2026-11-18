<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('ANAZORI_SQL_QA')!=='1')exit('Local SQL QA only.');
$db=new PDO('mysql:host=127.0.0.1;port=3317;charset=utf8mb4','root','Local-Only-2026!',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$database='anazori_qa_'.getenv('ANAZORI_QA_ID');if(!preg_match('/^anazori_qa_[0-9]+$/D',$database))exit('Invalid QA identity.');
$db->exec('CREATE DATABASE `'.$database.'` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');$db->exec('USE `'.$database.'`');
$db->exec(file_get_contents(__DIR__.'/../deploy/anazori-hostinger.sql'));
foreach(['az_orders','az_participants','az_tickets','st_expenses','submissions','users'] as $table)if((int)$db->query('SELECT COUNT(*) FROM '.$table)->fetchColumn()!==0)throw new RuntimeException('Operational data leaked into installation: '.$table);
echo 'PASS MariaDB import: '.count($db->query('SHOW TABLES')->fetchAll())." tables; no operational data or passwords.\n";
