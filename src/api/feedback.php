<?php
declare(strict_types=1);
require __DIR__ . '/../includes/portal-core.php';
try {
    $input = portal_input(); $db = portal_db(); portal_rate_limit($db,'feedback',3,600);
    $message = portal_text($input,'message',10,2000);
    $db->prepare('INSERT INTO feedback(id,message,created_at) VALUES(?,?,?)')->execute([bin2hex(random_bytes(10)),$message,gmdate('c')]);
    portal_json(['success'=>true,'message'=>'Thank you. Your feedback has been saved.'],201);
} catch (Throwable $error) { error_log('ANAZORI feedback storage error: ' . $error->getMessage()); portal_json(['success'=>false,'error'=>'Feedback could not be saved. Please try again later.'],503); }
