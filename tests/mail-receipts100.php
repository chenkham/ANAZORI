<?php
putenv('ANAZORI_PRIVATE_CONFIG=/nonexistent');putenv('ANAZORI_DB_DRIVER=sqlite');putenv('ANAZORI_DB_PATH=:memory:');putenv('ANAZORI_APP_KEY='.base64_encode(random_bytes(32)));putenv('ANAZORI_TEST_MODE=1');putenv('ANAZORI_MAIL_NOTIFICATIONS=1');
require __DIR__.'/../src/includes/commerce.php';
foreach(['interest_received','contribution_received','ticket_rejected'] as $kind)az_queue_mail89('disabled:'.$kind,$kind,['email'=>'test@example.invalid']);
if((int)cms_db()->query('SELECT COUNT(*) FROM az_mail_jobs89')->fetchColumn()!==0)throw new RuntimeException('Only the current three notification types may queue.');
if(!in_array('registration_received',ANAZORI_NOTICE_KINDS101,true))throw new RuntimeException('Registration receipts must be enabled.');
echo "PASS Registration receipts are enabled; interest/contribution and rejection notices stay excluded.\n";
