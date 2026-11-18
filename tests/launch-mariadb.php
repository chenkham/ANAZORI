<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('ANAZORI_MYSQL_QA')!=='1')exit('Explicit isolated MariaDB QA only.');
$root=new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;charset=utf8mb4','root','',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$env=array_filter(getenv(),fn($key)=>!str_starts_with($key,'ANAZORI_'),ARRAY_FILTER_USE_KEY);
$temp=sys_get_temp_dir().'/anazori-mysqlqa-'.getmypid();mkdir($temp,0700);
$qaUser='anazori_qa_'.getmypid();$qaPassword=bin2hex(random_bytes(24));
$root->exec('CREATE USER '.$root->quote($qaUser)."@'localhost' IDENTIFIED BY ".$root->quote($qaPassword));
try{
 foreach(['game-google','manual-payments','studio-access','studio-finance','launch52','form54'] as $index=>$test){
  $name='anazori_launchqa_'.getmypid().'_'.$index;
  $root->exec('CREATE DATABASE `'.$name.'` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
  try{
   $root->exec('USE `'.$name.'`');$root->exec(file_get_contents(__DIR__.'/../deploy/anazori-hostinger.sql'));
   $root->exec('GRANT ALL PRIVILEGES ON `'.$name.'`.* TO '.$root->quote($qaUser)."@'localhost'");
   foreach(['az_orders','az_participants','az_tickets','st_expenses','submissions','users','az_auth_events','az_challenges'] as $table)if((int)$root->query('SELECT COUNT(*) FROM '.$table)->fetchColumn())throw new RuntimeException('Operational records leaked into clean installation: '.$table);
   $testEnv=$env+['ANAZORI_PRIVATE_CONFIG'=>'/nonexistent','ANAZORI_DB_DRIVER'=>'mysql','ANAZORI_DB_HOST'=>'127.0.0.1','ANAZORI_DB_NAME'=>$name,'ANAZORI_DB_USER'=>$qaUser,'ANAZORI_DB_PASS'=>$qaPassword,'ANAZORI_TEST_MODE'=>'1','ANAZORI_SQL_QA'=>'1','ANAZORI_APP_ENV'=>'development','ANAZORI_SECRET_PATH'=>$temp.'/key'];
   $process=proc_open(['php',__DIR__.'/'.$test.'.php'],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,dirname(__DIR__),$testEnv);
   fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
   if(proc_close($process)!==0||!str_contains($output,'PASS'))throw new RuntimeException('MariaDB check failed: '.$test."\n".$errors.$output);
   echo trim($output)."\n";if($errors!=='')fwrite(STDERR,$errors);
  }finally{$root->exec('DROP DATABASE `'.$name.'`');}
 }
 echo "PASS Clean production SQL import, empty operational registers and six application suites on MariaDB.\n";
}finally{$root->exec('DROP USER '.$root->quote($qaUser)."@'localhost'");foreach(glob($temp.'/*')?:[] as $file)unlink($file);rmdir($temp);}
