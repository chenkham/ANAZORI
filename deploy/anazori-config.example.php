<?php
// Copy this file to the parent of public_html as anazori-config.php.
return [
    'ANAZORI_APP_ENV'=>'production',
    'ANAZORI_SITE_URL'=>'https://anazori.ccsdu.in',
    'ANAZORI_URL'=>'https://anazori.ccsdu.in',
    'ANAZORI_DB_DRIVER'=>'mysql',
    'ANAZORI_DB_HOST'=>'localhost',
    'ANAZORI_DB_PORT'=>'3306',
    'ANAZORI_DB_NAME'=>'YOUR_FULL_HOSTINGER_DATABASE_NAME',
    'ANAZORI_DB_USER'=>'YOUR_FULL_HOSTINGER_DATABASE_USER',
    'ANAZORI_DB_PASS'=>'YOUR_DATABASE_PASSWORD',
    'ANAZORI_BOOTSTRAP_PASSWORD'=>'REPLACE_WITH_A_NEW_RANDOM_PASSWORD_AT_LEAST_20_CHARACTERS',
    // Native PHP mail; all senders share the hosting account quota.
    'ANAZORI_PHP_MAIL_OTP_1'=>'noreply1@ccsdu.in',
    'ANAZORI_PHP_MAIL_OTP_2'=>'noreply2@ccsdu.in',
    'ANAZORI_PHP_MAIL_NOTICE_1'=>'noreply3@ccsdu.in',
    'ANAZORI_PHP_MAIL_NOTICE_2'=>'noreply4@ccsdu.in',
    'ANAZORI_PHP_MAIL_DAILY_LIMIT'=>'90',
    'ANAZORI_PHP_MAIL_PER_MINUTE'=>'8',
    'ANAZORI_PHP_MAIL_SENDER_DAILY_LIMIT'=>'45',
    'ANAZORI_PHP_MAIL_SENDER_PER_MINUTE'=>'4',
    'ANAZORI_MAIL_NOTIFICATIONS'=>'1', // Run src/includes/mail-worker95.php every minute.

    // Google credentials can also be saved through Studio > Integrations.
    'ANAZORI_GOOGLE_CLIENT_ID'=>'',
    'ANAZORI_GOOGLE_CLIENT_SECRET'=>'',
    'ANAZORI_SECRET_PATH'=>__DIR__.'/anazori-private/application-key',
    'ANAZORI_PAYMENT_PROOF_DIR'=>__DIR__.'/anazori-private/payment-proofs',
    'ANAZORI_REGISTRATION_FILE_DIR'=>__DIR__.'/anazori-private/registration-files',
    'ANAZORI_STUDIO_RECEIPT_PATH'=>__DIR__.'/anazori-private/studio-receipts',
];
