<?php
declare(strict_types=1);

/** Serialise email and Google signup on the same platform lock. */
function az_password_signup99(PDO $db,string $email,string $name,string $password): array {
    $email=strtolower(trim($email));
    if(!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($email)>254)throw new InvalidArgumentException('Enter a valid email address.');
    $db->beginTransaction();
    try {
        az_lock($db);
        $query=$db->prepare('SELECT id FROM az_participants WHERE LOWER(email)=? LIMIT 1');
        $query->execute([$email]);
        if($query->fetchColumn())throw new RuntimeException('An account already exists with this email. Please sign in.');
        if(!az_mail_delivery_available())throw new RuntimeException('Email signup is waiting for verification email setup. Please continue with Google or contact the organisers.');
        az_password($password);
        $name=trim($name);
        if(mb_strlen($name)<2||mb_strlen($name)>100||preg_match('/[<>\x00-\x1F]/u',$name))throw new InvalidArgumentException('Enter your full name.');
        $db->prepare('INSERT INTO az_participants(email,name,password_hash,created_at,profile_completed) VALUES(?,?,?,?,1)')->execute([$email,$name,password_hash($password,PASSWORD_DEFAULT),gmdate('c')]);
        $query=$db->prepare('SELECT * FROM az_participants WHERE id=?');
        $query->execute([$db->lastInsertId()]);
        $participant=$query->fetch();
        $db->commit();
        return $participant;
    }catch(Throwable $error){
        if($db->inTransaction())$db->rollBack();
        throw $error;
    }
}

/** Recover the current code only for this authenticated participant and email. */
function az_pending_verification99(array $participant): ?array {
    $query=cms_db()->prepare("SELECT id,expires_at FROM az_challenges WHERE kind='VERIFY' AND user_kind='participant' AND user_id=? AND email_hash=? AND consumed=0 AND attempts<5 AND expires_at>? ORDER BY created_at DESC LIMIT 1");
    $query->execute([(int)$participant['id'],hash('sha256',strtolower($participant['email'])),time()]);
    $challenge=$query->fetch();
    unset($_SESSION['verify_challenge']);
    if(!$challenge)return null;
    $_SESSION['verify_challenge']=$challenge['id'];
    $_SESSION['az_challenges'][$challenge['id']]=true;
    return $challenge;
}
