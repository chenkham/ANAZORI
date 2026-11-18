<?php
declare(strict_types=1);

function az_certificate_table_sql(PDO $db, string $table): string {
    if (!preg_match('/^[a-z0-9_]+$/D',$table)) throw new InvalidArgumentException('Invalid certificate table name.');
    $sqlite = $db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
    $id = $sqlite ? 'INTEGER PRIMARY KEY AUTOINCREMENT' : 'INT AUTO_INCREMENT PRIMARY KEY';
    $text = $sqlite ? 'TEXT' : 'MEDIUMTEXT';
    return "CREATE TABLE IF NOT EXISTS $table (
        id $id,
        certificate_id VARCHAR(40) NOT NULL UNIQUE,
        token_hash VARCHAR(64) NOT NULL UNIQUE,
        token_enc $text NOT NULL,
        event_id INT NOT NULL,
        order_id INT NOT NULL,
        participant_id INT NOT NULL,
        recipient_email VARCHAR(254) NOT NULL,
        recipient_name VARCHAR(150) NOT NULL,
        team_name VARCHAR(120) NOT NULL DEFAULT '',
        institution VARCHAR(180) NOT NULL DEFAULT '',
        status VARCHAR(20) NOT NULL DEFAULT 'ISSUED',
        issued_by INT NOT NULL,
        issued_at VARCHAR(40) NOT NULL,
        updated_at VARCHAR(40) NOT NULL
    )";
}

function az_certificate_allow_team_members(PDO $db): void {
    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='certificates_team_members_schema'")->fetchColumn() === '1') return;
    $columns = ['event_id','participant_id'];
    if ($db->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
        $requiresRebuild = false;
        foreach ($db->query('PRAGMA index_list("az_certificates")')->fetchAll(PDO::FETCH_ASSOC) as $index) {
            if (!(int)$index['unique'] || !preg_match('/^[a-zA-Z0-9_]+$/D',(string)$index['name'])) continue;
            $info = $db->query('PRAGMA index_info("'.$index['name'].'")')->fetchAll(PDO::FETCH_ASSOC);
            usort($info,fn($a,$b)=>(int)$a['seqno']<=>(int)$b['seqno']);
            if (array_column($info,'name') === $columns) { $requiresRebuild = true; break; }
        }
        if ($requiresRebuild) {
            $fields = 'id,certificate_id,token_hash,token_enc,event_id,order_id,participant_id,recipient_email,recipient_name,team_name,institution,status,issued_by,issued_at,updated_at';
            $db->beginTransaction();
            try {
                $db->exec(az_certificate_table_sql($db,'az_certificates_team_members_migration'));
                $db->exec('INSERT INTO az_certificates_team_members_migration('.$fields.') SELECT '.$fields.' FROM az_certificates');
                $db->exec('DROP TABLE az_certificates');
                $db->exec('ALTER TABLE az_certificates_team_members_migration RENAME TO az_certificates');
                $db->commit();
            } catch (Throwable $error) {
                if ($db->inTransaction()) $db->rollBack();
                throw $error;
            }
        }
    } else {
        $indexes = [];
        foreach ($db->query('SHOW INDEX FROM az_certificates')->fetchAll(PDO::FETCH_ASSOC) as $index) {
            if (!(int)$index['Non_unique']) $indexes[$index['Key_name']][(int)$index['Seq_in_index']] = $index['Column_name'];
        }
        foreach ($indexes as $name=>$indexColumns) {
            ksort($indexColumns);
            if (array_values($indexColumns) === $columns && preg_match('/^[a-zA-Z0-9_]+$/D',(string)$name)) {
                $db->exec('ALTER TABLE az_certificates DROP INDEX `'.$name.'`');
                break;
            }
        }
    }
    cms_put_setting('certificates_team_members_schema','1');
}

function az_install_certificates(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS az_certificate_awards (
        event_id INT NOT NULL,
        team_key VARCHAR(190) NOT NULL,
        team_name VARCHAR(120) NOT NULL,
        place INT NOT NULL,
        updated_by INT NOT NULL,
        updated_at VARCHAR(40) NOT NULL,
        PRIMARY KEY (event_id, team_key)
    )");
    $db->exec(az_certificate_table_sql($db,'az_certificates'));
    az_certificate_allow_team_members($db);

    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='certificates_schema'")->fetchColumn() !== '1') {
        $db->beginTransaction();
        try {
            az_lock($db);
            $event = $db->query("SELECT id FROM cms_content WHERE type='event' AND (slug IN ('goc','game-of-codes') OR LOWER(title) LIKE '%game of codes%') ORDER BY CASE slug WHEN 'goc' THEN 0 ELSE 1 END LIMIT 1")->fetchColumn();
            if ($event) {
                $check = $db->prepare('SELECT COUNT(*) FROM az_certificate_awards WHERE event_id=?');
                $check->execute([(int)$event]);
                if (!(int)$check->fetchColumn()) {
                    $insert = $db->prepare('INSERT INTO az_certificate_awards(event_id,team_key,team_name,place,updated_by,updated_at) VALUES(?,?,?,?,0,?)');
                    foreach ([[1,'Char Titans'],[2,'Buri Buri Zaemon'],[2,'Winter is Compiling'],[3,'Sideman']] as [$place,$team]) {
                        $insert->execute([(int)$event,az_certificate_team_key($team),$team,$place,gmdate('c')]);
                    }
                }
            }
            cms_put_setting('certificates_schema','1');
            $db->commit();
        } catch (Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }
    az_certificate_sync_goc_awards($db);
}

function az_certificate_team_key(string $team): string {
    $team = mb_strtolower(trim(preg_replace('/\s+/u',' ',$team) ?? $team));
    return preg_replace('/[^\pL\pN]+/u','',$team) ?? $team;
}

function az_certificate_order_team_name(array $order): string {
    $snapshot = json_decode((string)($order['snapshot']??$order['order_snapshot']??''),true) ?: [];
    $team = trim((string)($snapshot['team_name']??''));
    if ($team !== '') return $team;
    $answers = json_decode((string)($order['answers']??$order['order_answers']??''),true) ?: [];
    foreach ($answers as $label=>$value) {
        $label=preg_replace('/[_-]+/u',' ',(string)$label)??(string)$label;
        if (!preg_match('/^\s*team\s*$|\bteam\s*name\b|\bteam\s*\/\s*project\s*name\b|\bname\s+of\s+(?:the\s+)?team\b/iu',$label) || !is_scalar($value)) continue;
        $team = trim((string)$value);
        if ($team !== '' && mb_strlen($team)<=120 && !preg_match('/[\x00-\x1F]/u',$team)) return $team;
    }
    return '';
}

function az_certificate_apply_registered_team_name(array $certificate): array {
    $team = az_certificate_order_team_name($certificate);
    if ($team !== '') $certificate['team_name'] = $team;
    return $certificate;
}

function az_certificate_sync_goc_awards(PDO $db): void {
    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='certificates_goc_awards_v2'")->fetchColumn() === '1') return;
    $events = $db->query("SELECT id FROM cms_content WHERE type='event' AND (slug IN ('goc','game-of-codes') OR LOWER(title) LIKE '%game of codes%')")->fetchAll(PDO::FETCH_COLUMN);
    if (!$events) return;
    $db->beginTransaction();
    try {
        az_lock($db);
        $find = $db->prepare('SELECT team_key,team_name FROM az_certificate_awards WHERE event_id=?');
        $update = $db->prepare('UPDATE az_certificate_awards SET team_key=?,team_name=?,place=?,updated_by=0,updated_at=? WHERE event_id=? AND team_key=?');
        $delete = $db->prepare('DELETE FROM az_certificate_awards WHERE event_id=? AND team_key=?');
        $insert = $db->prepare('INSERT INTO az_certificate_awards(event_id,team_key,team_name,place,updated_by,updated_at) VALUES(?,?,?, ?,0,?)');
        foreach ($events as $eventId) {
            $find->execute([(int)$eventId]);
            $existing = $find->fetchAll(PDO::FETCH_ASSOC);
            foreach ([[1,'Char Titans'],[2,'Buri Buri Zaemon'],[2,'Winter is Compiling'],[3,'Sideman']] as [$place,$team]) {
                $key = az_certificate_team_key($team);
                $matches = array_values(array_filter($existing,static fn($row)=>az_certificate_team_key((string)$row['team_name'])===$key||az_certificate_team_key((string)$row['team_key'])===$key));
                if (!$matches) $insert->execute([(int)$eventId,$key,$team,$place,gmdate('c')]);
                else {
                    $canonicalKey = null;
                    foreach ($matches as $match) if ((string)$match['team_key']===$key) {$canonicalKey=$key;break;}
                    $canonicalKey ??= (string)$matches[0]['team_key'];
                    $update->execute([$key,$team,$place,gmdate('c'),(int)$eventId,$canonicalKey]);
                    foreach ($matches as $match) if ((string)$match['team_key']!==$canonicalKey) $delete->execute([(int)$eventId,(string)$match['team_key']]);
                }
            }
        }
        cms_put_setting('certificates_goc_awards_v2','1');
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

function az_certificate_require_manage(array $staff, int $eventId): array {
    $staff = st_refresh_user($staff);
    if ($staff['must_change_password'] || !cms_can($staff,'tickets','revoke')) throw new RuntimeException('You do not have access to manage event certificates.');
    st_require_event($staff,$eventId);
    return $staff;
}

function az_certificate_awards(int $eventId): array {
    $query = cms_db()->prepare('SELECT team_key,team_name,place FROM az_certificate_awards WHERE event_id=? ORDER BY place,team_name');
    $query->execute([$eventId]);
    return $query->fetchAll();
}

function az_certificate_award(int $eventId, string $team): array {
    $key = az_certificate_team_key($team);
    if ($key !== '') foreach (az_certificate_awards($eventId) as $award) {
        if (az_certificate_team_key((string)$award['team_name']) === $key || az_certificate_team_key((string)$award['team_key']) === $key) {
            $place = (int)$award['place'];
            $short = match($place) {1=>'1st',2=>'2nd',3=>'3rd',default=>$place.'th'};
            return ['status'=>'Winner','label'=>$short.' Place','place'=>$place];
        }
    }
    return ['status'=>'Participant','label'=>'Participant','place'=>0];
}

function az_certificate_event_orders(array $staff, int $eventId): array {
    st_require_event($staff,$eventId);
    $query = cms_db()->prepare("SELECT o.id,o.public_id,o.participant_id,o.event_id,o.snapshot,o.answers,o.created_at,
        p.name account_name,p.email account_email
        FROM az_orders o JOIN az_participants p ON p.id=o.participant_id
        WHERE o.event_id=? AND o.state='PAID' AND o.environment='live'
        AND EXISTS (SELECT 1 FROM az_tickets t WHERE t.order_id=o.id AND t.status IN ('VALID','USED'))
        ORDER BY o.id");
    $query->execute([$eventId]);
    return $query->fetchAll();
}

function az_certificate_rows(array $staff, int $eventId): array {
    st_require_event($staff,$eventId);
    $query = cms_db()->prepare('SELECT c.*,o.snapshot order_snapshot,o.answers order_answers FROM az_certificates c LEFT JOIN az_orders o ON o.id=c.order_id WHERE c.event_id=? ORDER BY c.recipient_name,c.id');
    $query->execute([$eventId]);
    return array_map('az_certificate_apply_registered_team_name',$query->fetchAll());
}

function az_certificate_team_member_names(array $order): array {
    $answers = json_decode((string)($order['answers']??''),true) ?: [];
    $snapshot = json_decode((string)($order['snapshot']??''),true) ?: [];
    $leaderName = trim((string)($snapshot['name']??''));
    if (isset($order['account_name']) && trim((string)$order['account_name'])!=='') $leaderName=trim((string)$order['account_name']);
    elseif (!empty($order['participant_id'])) {
        $query=cms_db()->prepare('SELECT name FROM az_participants WHERE id=?');
        $query->execute([(int)$order['participant_id']]);
        $leaderName=trim((string)($query->fetchColumn()?:$leaderName));
    }
    $leaderKey=mb_strtolower(preg_replace('/\s+/u',' ',$leaderName)??$leaderName);
    $names=[];
    foreach ($answers as $label=>$value) {
        $label=mb_strtolower(preg_replace('/[_-]+/u',' ',(string)$label)??(string)$label);
        $memberField = preg_match('/\b(?:team\s*)?members?\b|\bteammates?\b|\bparticipants?\b/u',$label);
        $plainMemberList = $memberField && !preg_match('/\b(?:count|number|size|how many|email|phone|contact|role|position|college|school)\b/u',$label);
        $nameField = preg_match('/\bnames?\b/u',$label)
            || preg_match('/\b(?:team\s*)?(?:member|teammate|participant)\s*(?:#?\d+)?\s*$/u',$label)
            || $plainMemberList;
        if (!$memberField || !$nameField) continue;
        $values=is_array($value)?$value:[$value];
        foreach ($values as $item) {
            if (!is_scalar($item)) continue;
            $item=trim((string)$item);
            if ($item==='' || filter_var($item,FILTER_VALIDATE_EMAIL)) continue;
            $parts=preg_split('/[\r\n;]+/u',$item,-1,PREG_SPLIT_NO_EMPTY)?:[];
            if ($plainMemberList || preg_match('/\b(?:all|full|team|teammates?|participants?|members?)\b.*\bnames?\b/u',$label)) {
                $expanded=[];
                foreach($parts as $part) foreach(preg_split('/\s*,\s*/u',$part,-1,PREG_SPLIT_NO_EMPTY)?:[] as $namePart)$expanded[]=$namePart;
                $parts=$expanded;
            }
            foreach($parts as $name){
                $name=trim((string)$name);
                $name=preg_replace('/\s*(?:\||\s+-\s+|,)?\s*\(?[^\s@(),]+@[^\s@(),]+\)?\s*$/u','',$name)??$name;
                $name=preg_replace('/^\s*(?:(?:team\s*)?(?:member|teammate|participant)\s*)?(?:#?\d+\s*)?(?:name\s*)?[:.)-]\s*/iu','',$name)??$name;
                $name=trim($name," \t\n\r\0\x0B,;");
                if($name===''||mb_strlen($name)>150||preg_match('/[\x00-\x1F@]/u',$name)||!preg_match('/\p{L}/u',$name))continue;
                $key=mb_strtolower(preg_replace('/\s+/u',' ',$name)??$name);
                if($key===$leaderKey)continue;
                $names[$key]=$name;
            }
        }
    }
    return array_values($names);
}

function az_certificate_issue_order(array $actor, int $eventId, int $orderId, string $emailInput, string $nameInput, string $institutionInput): string {
    $db = cms_db();
    $db->beginTransaction();
    try {
        az_lock($db);
        $actor = az_certificate_require_manage($actor,$eventId);
        $order = st_require_order($actor,$orderId);
        if ((int)$order['event_id'] !== $eventId || $order['state'] !== 'PAID' || $order['environment'] !== 'live') throw new RuntimeException('Certificates are available for confirmed live registrations only.');
        $ticket = $db->prepare("SELECT id FROM az_tickets WHERE order_id=? AND status IN ('VALID','USED') LIMIT 1");
        $ticket->execute([$orderId]);
        if (!$ticket->fetchColumn()) throw new RuntimeException('This registration has no active ticket.');

        $snapshot = json_decode($order['snapshot'],true) ?: [];
        $owner = $db->prepare('SELECT id,email,name,active FROM az_participants WHERE id=?');
        $owner->execute([(int)$order['participant_id']]);
        $ownerAccount = $owner->fetch();
        if (!$ownerAccount) throw new RuntimeException('The registration account is unavailable.');
        $defaultName = (string)$ownerAccount['name'] !== '' ? (string)$ownerAccount['name'] : (string)($snapshot['name'] ?? '');
        $name = trim($nameInput !== '' ? $nameInput : $defaultName);
        if ($name === '' || mb_strlen($name)>150 || preg_match('/[\x00-\x1F]/u',$name)) throw new InvalidArgumentException('Enter the participant’s full name.');
        $team = az_certificate_order_team_name($order);
        $email = strtolower(trim($emailInput));
        if ($email === '') {
            if (!$team || $nameInput === '') $email = strtolower(trim((string)$ownerAccount['email']));
            if (!(int)$ownerAccount['active']) throw new RuntimeException('The team leader’s registration account is no longer active.');
            $participantId = (int)$ownerAccount['id'];
        } else {
            if (!filter_var($email,FILTER_VALIDATE_EMAIL) || mb_strlen($email)>254) throw new InvalidArgumentException('Enter a valid participant account email address.');
            $account = $db->prepare('SELECT id FROM az_participants WHERE LOWER(email)=? AND active=1 LIMIT 1');
            $account->execute([$email]);
            $participantId = $account->fetchColumn();
            if (!$participantId) throw new RuntimeException('That participant needs an active Anazori account. Leave email blank to keep their certificate in the team leader’s dashboard.');
        }
        $institution = '';

        if ($team !== '') {
            $existing = $db->prepare('SELECT id FROM az_certificates WHERE event_id=? AND order_id=? AND participant_id=? AND LOWER(recipient_name)=? AND LOWER(recipient_email)=? LIMIT 1');
            $existing->execute([$eventId,$orderId,(int)$participantId,mb_strtolower($name),mb_strtolower($email)]);
        } else {
            $existing = $db->prepare('SELECT id FROM az_certificates WHERE event_id=? AND participant_id=?');
            $existing->execute([$eventId,(int)$participantId]);
        }
        $now = gmdate('c');
        if ($existingId = $existing->fetchColumn()) {
            $db->prepare("UPDATE az_certificates SET order_id=?,recipient_email=?,recipient_name=?,team_name=?,institution=?,status='ISSUED',issued_by=?,updated_at=? WHERE id=?")
                ->execute([$orderId,$email,$name,$team,$institution,(int)$actor['id'],$now,(int)$existingId]);
            $certificateId = $db->prepare('SELECT certificate_id FROM az_certificates WHERE id=?');
            $certificateId->execute([(int)$existingId]);
            $publicId = (string)$certificateId->fetchColumn();
        } else {
            $token = bin2hex(random_bytes(32));
            $publicId = 'AZ-CERT-'.strtoupper(bin2hex(random_bytes(5)));
            $db->prepare("INSERT INTO az_certificates(certificate_id,token_hash,token_enc,event_id,order_id,participant_id,recipient_email,recipient_name,team_name,institution,status,issued_by,issued_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,'ISSUED',?,?,?)")
                ->execute([$publicId,hash('sha256',$token),az_encrypt($token),$eventId,$orderId,(int)$participantId,$email,$name,$team,$institution,(int)$actor['id'],$now,$now]);
        }
        st_event_audit($actor,$eventId,'certificate.issue',$publicId.' · '.$name.($team?' · '.$team:''));
        cms_audit($actor,'certificate.issue',$publicId.' · '.$name);
        $db->commit();
        return $publicId;
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

function az_certificate_issue_team_members(array $actor, int $eventId, int $orderId): array {
    $actor = az_certificate_require_manage($actor,$eventId);
    $order = st_require_order($actor,$orderId);
    $snapshot = json_decode($order['snapshot'],true) ?: [];
    if ((int)$order['event_id']!==$eventId || $order['state']!=='PAID' || $order['environment']!=='live' || az_certificate_order_team_name($order)==='') {
        throw new RuntimeException('Choose a confirmed team registration to issue teammate certificates.');
    }
    $members=az_certificate_team_member_names($order);
    if(count($members)>10)throw new RuntimeException('The registration contains more than 10 teammate names. Review the saved member fields before issuing certificates.');
    $issued = [az_certificate_issue_order($actor,$eventId,$orderId,'','','')];
    foreach ($members as $name) $issued[] = az_certificate_issue_order($actor,$eventId,$orderId,'',$name,'');
    return $issued;
}

function az_certificate_staff_people(): array {
    return [
        'utpala'=>[
            'name'=>'Dr. Utpala Borgohain',
            'role'=>'Teacher Coordinator',
            'ccsdu_profile'=>'https://ccsdu.in/faculty.php',
            'university_profile'=>'https://www.dibru.ac.in/user-profile/utpala-borgohain',
        ],
        'rizwan'=>[
            'name'=>'Dr. Rizwan Rehman',
            'role'=>'Teacher Coordinator',
            'ccsdu_profile'=>'https://ccsdu.in/faculty.php',
            'university_profile'=>'https://www.dibru.ac.in/user-profile/rizwan-rehman',
        ],
    ];
}

function az_certificate_is_staff_certificate(array $certificate): bool {
    return (int)($certificate['order_id']??-1)===0
        && (int)($certificate['participant_id']??-1)===0
        && ($certificate['institution']??'')==='Teacher Coordinator';
}

function az_certificate_staff_certificates(int $eventId): array {
    $query=cms_db()->prepare("SELECT c.*,e.title AS event_title,e.slug AS event_slug,'' AS order_snapshot,'' AS order_answers
        FROM az_certificates c JOIN cms_content e ON e.id=c.event_id AND e.type='event'
        WHERE c.event_id=? AND c.order_id=0 AND c.participant_id=0 AND c.institution='Teacher Coordinator'
        ORDER BY c.recipient_name,c.id");
    $query->execute([$eventId]);
    $rows=[];
    foreach($query->fetchAll() as $certificate) $rows[az_certificate_staff_key_for_name((string)$certificate['recipient_name'])]=$certificate;
    return $rows;
}

function az_certificate_staff_key_for_name(string $name): string {
    foreach(az_certificate_staff_people() as $key=>$person) if(mb_strtolower(trim($name))===mb_strtolower($person['name'])) return $key;
    return '';
}

function az_certificate_issue_staff(array $actor, int $eventId, string $personKey): string {
    $person=az_certificate_staff_people()[$personKey]??null;
    if(!$person) throw new InvalidArgumentException('Choose a listed teacher coordinator.');
    $db=cms_db();
    $db->beginTransaction();
    try {
        az_lock($db);
        $actor=az_certificate_require_manage($actor,$eventId);
        $event=cms_record($eventId);
        if(!$event||$event['type']!=='event'||(!in_array($event['slug'],['goc','game-of-codes'],true)&&stripos((string)$event['title'],'Game of Codes')===false)) throw new RuntimeException('Teacher coordinator certificates are only available in the Game of Codes workspace.');
        $find=$db->prepare("SELECT id,certificate_id FROM az_certificates WHERE event_id=? AND order_id=0 AND participant_id=0 AND institution='Teacher Coordinator' AND recipient_name=? ORDER BY id DESC LIMIT 1");
        $find->execute([$eventId,$person['name']]);
        $existing=$find->fetch();
        $now=gmdate('c');
        if($existing){
            $db->prepare("UPDATE az_certificates SET status='ISSUED',issued_by=?,updated_at=? WHERE id=?")
                ->execute([(int)$actor['id'],$now,(int)$existing['id']]);
            $publicId=(string)$existing['certificate_id'];
        } else {
            $token=bin2hex(random_bytes(32));
            $publicId='AZ-CERT-'.strtoupper(bin2hex(random_bytes(5)));
            $db->prepare("INSERT INTO az_certificates(certificate_id,token_hash,token_enc,event_id,order_id,participant_id,recipient_email,recipient_name,team_name,institution,status,issued_by,issued_at,updated_at)
                VALUES(?,?,?,?,0,0,'',?,'','Teacher Coordinator','ISSUED',?,?,?)")
                ->execute([$publicId,hash('sha256',$token),az_encrypt($token),$eventId,$person['name'],(int)$actor['id'],$now,$now]);
        }
        st_event_audit($actor,$eventId,'certificate.issue_staff',$publicId.' · '.$person['name']);
        cms_audit($actor,'certificate.issue_staff',$publicId.' · '.$person['name']);
        $db->commit();
        return $publicId;
    } catch(Throwable $error) {
        if($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

function az_certificate_set_status(array $actor, int $certificateRowId, bool $issue): void {
    $db = cms_db();
    $db->beginTransaction();
    try {
        az_lock($db);
        $actor = st_refresh_user($actor);
        if ($actor['must_change_password'] || !cms_can($actor,'tickets','revoke')) throw new RuntimeException('You do not have access to manage event certificates.');
        $query = $db->prepare('SELECT event_id,certificate_id FROM az_certificates WHERE id=?');
        $query->execute([$certificateRowId]);
        $certificate = $query->fetch();
        if (!$certificate) throw new RuntimeException('Certificate unavailable.');
        $actor = az_certificate_require_manage($actor,(int)$certificate['event_id']);
        $status = $issue ? 'ISSUED' : 'REVOKED';
        $db->prepare('UPDATE az_certificates SET status=?,updated_at=?,issued_by=? WHERE id=?')->execute([$status,gmdate('c'),(int)$actor['id'],$certificateRowId]);
        st_event_audit($actor,(int)$certificate['event_id'],'certificate.'.strtolower($status),$certificate['certificate_id']);
        cms_audit($actor,'certificate.'.strtolower($status),$certificate['certificate_id']);
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

function az_certificate_lookup_for_participant(string $certificateId, array $participant): ?array {
    $query = cms_db()->prepare("SELECT c.*,e.title event_title,e.slug event_slug,o.snapshot order_snapshot,o.answers order_answers FROM az_certificates c
        JOIN cms_content e ON e.id=c.event_id AND e.type='event'
        LEFT JOIN az_orders o ON o.id=c.order_id
        WHERE c.certificate_id=? AND c.status='ISSUED' AND (
            c.participant_id=? OR (c.team_name<>'' AND EXISTS (
                SELECT 1 FROM az_orders o WHERE o.id=c.order_id AND o.participant_id=?
            ))
        )");
    $query->execute([$certificateId,(int)$participant['id'],(int)$participant['id']]);
    $certificate = $query->fetch();
    return $certificate ? az_certificate_apply_registered_team_name($certificate) : null;
}

function az_certificate_team_rows_for_participant(int $orderId, array $participant): array {
    $query = cms_db()->prepare("SELECT c.*,e.title event_title,e.slug event_slug,o.snapshot order_snapshot,o.answers order_answers FROM az_certificates c
        JOIN cms_content e ON e.id=c.event_id AND e.type='event'
        JOIN az_orders o ON o.id=c.order_id
        WHERE c.order_id=? AND o.participant_id=? AND c.status='ISSUED'
        ORDER BY c.recipient_name,c.id");
    $query->execute([$orderId,(int)$participant['id']]);
    return array_values(array_filter(array_map('az_certificate_apply_registered_team_name',$query->fetchAll()),static fn($certificate)=>trim((string)$certificate['team_name'])!==''));
}

function az_certificate_lookup_token(string $token): ?array {
    if (!preg_match('/^[a-f0-9]{64}$/D',$token)) return null;
    $query = cms_db()->prepare('SELECT c.*,e.title event_title,e.slug event_slug,o.snapshot order_snapshot,o.answers order_answers FROM az_certificates c JOIN cms_content e ON e.id=c.event_id AND e.type=\'event\' LEFT JOIN az_orders o ON o.id=c.order_id WHERE c.token_hash=?');
    $query->execute([hash('sha256',$token)]);
    $certificate = $query->fetch();
    return $certificate ? az_certificate_apply_registered_team_name($certificate) : null;
}

function az_certificate_asset_data(string $name): string {
    static $cache = [];
    if (isset($cache[$name])) return $cache[$name];
    if (!preg_match('/^[a-z0-9-]+\.(?:png|jpe?g|svg)$/D',$name)) throw new InvalidArgumentException('Invalid certificate artwork.');
    $path = __DIR__.'/../assets/2026/certificate/'.$name;
    if (!is_file($path)) throw new RuntimeException('Certificate artwork is missing. Upload the complete certificate asset folder.');
    $mime = str_ends_with($name,'.svg') ? 'image/svg+xml' : (str_ends_with($name,'.jpg') || str_ends_with($name,'.jpeg') ? 'image/jpeg' : 'image/png');
    return $cache[$name] = 'data:'.$mime.';base64,'.base64_encode((string)file_get_contents($path));
}

function az_certificate_qr(string $token, bool $preview = false): string {
    $options = new chillerlan\QRCode\QROptions([
        'outputType'=>chillerlan\QRCode\QRCode::OUTPUT_MARKUP_SVG,
        'outputBase64'=>false,
        'eccLevel'=>chillerlan\QRCode\QRCode::ECC_M,
        'svgAddXmlHeader'=>false,
        'drawLightModules'=>true,
        'addQuietzone'=>true,
        'quietzoneSize'=>4,
    ]);
    $payload = $preview ? 'PREVIEW ONLY — NOT A VALID CERTIFICATE' : az_origin().'/certificate-verify.php?token='.rawurlencode($token);
    return (new chillerlan\QRCode\QRCode($options))->render($payload);
}

function az_certificate_pdf_units(string $value): string {
    $converted = preg_replace_callback('/calc\(var\(--u\)\s*\*\s*([0-9]+(?:\.[0-9]+)?)\)/', static function(array $match): string {
        $millimetres = rtrim(rtrim(number_format(((float)$match[1])*297/1308, 6, '.', ''), '0'), '.');
        return $millimetres.'mm';
    }, $value);
    return is_string($converted) ? $converted : $value;
}

function az_certificate_styles(bool $pdf = false): string {
    $base = file_get_contents(__DIR__.'/../assets/2026/certificate/certificate.css');
    $design = file_get_contents(__DIR__.'/../assets/2026/certificate/goc-certificate.css');
    if (!is_string($base) || !is_string($design)) throw new RuntimeException('Certificate styles are unavailable.');
    if ($pdf) $design = az_certificate_pdf_units($design);
    return $base."\n".$design;
}

function az_certificate_markup(array $certificate, array $award, string $qr, bool $pdf = false): string {
    $awardPlace = match((int)($award['place']??0)) {1=>'First',2=>'Second',3=>'Third',default=>(string)($award['label']??'')};
    $isGocEvent = in_array($certificate['event_slug']??'', ['goc','game-of-codes'],true) || stripos((string)($certificate['event_title']??''),'Game of Codes')!==false;
    $eventText = $isGocEvent ? 'Game of Codes — Full Stack Gen AI Hackathon' : (string)($certificate['event_title']??'the event');
    $staffCertificate = az_certificate_is_staff_certificate($certificate);
    $hasTeam = trim((string)($certificate['team_name']??'')) !== '';
    $winner = ($award['status']??'') === 'Winner';
    $recipient = (string)($certificate['recipient_name']??'');
    $recipientLength = function_exists('mb_strlen') ? mb_strlen($recipient,'UTF-8') : strlen($recipient);
    $recipientClass = $recipientLength > 40 ? 'goc-recipient-extra-long' : ($recipientLength > 26 ? 'goc-recipient-long' : '');
    $teamLine = $hasTeam ? 'Team: <strong>'.e($certificate['team_name']).'</strong>' : e($eventText);
    if ($staffCertificate) {
        $lines = [
            'has successfully served as the Teacher Coordinator for '.e($eventText),
            'organised as part of ANAZORI V16.0 - 2026, the Annual Technical Fest of',
            'the Centre for Computer Science and Applications, Dibrugarh University.',
        ];
        $foot = 'Your guidance and support helped make Game of Codes a success.';
    } elseif ($winner) {
        $lines = [
            $teamLine,
            'secured <strong>'.e($awardPlace).' Place</strong> in '.e($eventText),
            'as part of ANAZORI V16.0 - 2026, the Annual Technical Fest of',
            'the Centre for Computer Science and Applications, Dibrugarh University.',
        ];
        $foot = 'Congratulations on securing '.e($awardPlace).' Place!';
    } else {
        $lines = [
            $teamLine,
            'has participated in '.e($eventText),
            'as part of ANAZORI V16.0 - 2026, the Annual Technical Fest of',
            'the Centre for Computer Science and Applications, Dibrugarh University.',
        ];
        $foot = 'We appreciate your active involvement and wish you continued success.';
    }
    $body = '<div class="goc-certificate-body">';
    foreach ($lines as $index=>$line) $body .= '<div class="goc-copy-line" style="top:calc(var(--u)*'.($index*32).')">'.$line.'</div>';
    $body .= '</div>';
    $templateName = $staffCertificate ? 'goc-design-staff.jpg' : ($winner ? 'goc-design-winner.jpg' : 'goc-design-participant.jpg');
    $templatePath = __DIR__.'/../assets/2026/certificate/'.$templateName;
    $template = $pdf ? az_certificate_asset_data($templateName) : '/assets/2026/certificate/'.$templateName.'?v='.(is_file($templatePath)?filemtime($templatePath):'1');
    $presentation = $staffCertificate ? 'This is to certify that' : 'This certificate is proudly presented to';
    $copy = '<div class="goc-pres">'.$presentation.'</div>'
        .'<div class="goc-name '.$recipientClass.'">'.e($recipient).'</div><div class="goc-name-rule"></div><div class="goc-name-rule-small"></div>'
        .$body.'<div class="goc-foot">'.$foot.'</div>';
    $qrSource = 'data:image/svg+xml;base64,'.base64_encode($qr);
    $qrMarkup = '<img class="goc-cert-qr" src="'.$qrSource.'" alt="">';
    $markup = '<div class="certificate-sheet certificate-goc '.($pdf?'certificate-pdf':'certificate-web').'">'
        .'<img class="certificate-template" src="'.$template.'" alt="">'.$copy.$qrMarkup.'</div>';
    return $pdf ? az_certificate_pdf_units($markup) : $markup;
}

function az_certificate_stream_pdf(array $certificate, array $award, string $qr, bool $preview = false): never {
    $css = az_certificate_styles(true);
    $html = '<!doctype html><html><head><meta charset="utf-8"><style>'.$css.'</style></head><body class="certificate-document">'.az_certificate_markup($certificate,$award,$qr,true).'</body></html>';
    $options = new Dompdf\Options();
    $options->set('isRemoteEnabled',false);
    $options->set('isPhpEnabled',false);
    $options->set('isJavascriptEnabled',false);
    $options->set('tempDir',sys_get_temp_dir());
    $pdf = new Dompdf\Dompdf($options);
    $pdf->setPaper('A4','landscape');
    $pdf->loadHtml($html,'UTF-8');
    $pdf->render();
    header('Cache-Control: private, no-store');
    $pdf->stream(($preview ? 'Preview-Certificate' : $certificate['certificate_id']).'.pdf',['Attachment'=>true]);
    exit;
}

function az_certificate_stream_team_pdf(array $certificates, string $teamName): never {
    if (!$certificates) throw new RuntimeException('There are no issued certificates in this team yet.');
    $css = az_certificate_styles(true);
    $pages = '';
    $last = count($certificates)-1;
    foreach (array_values($certificates) as $index=>$certificate) {
        $award = az_certificate_award((int)$certificate['event_id'],(string)$certificate['team_name']);
        $qr = az_certificate_qr(az_decrypt($certificate['token_enc']));
        $markup = az_certificate_markup($certificate,$award,$qr,true);
        $class = $index===$last ? 'certificate-last' : 'certificate-next';
        $pages .= str_replace('class="certificate-sheet certificate-goc certificate-pdf"','class="certificate-sheet certificate-goc certificate-pdf '.$class.'"',$markup);
    }
    $html = '<!doctype html><html><head><meta charset="utf-8"><style>'.$css.'</style></head><body class="certificate-document">'.$pages.'</body></html>';
    $options = new Dompdf\Options();
    $options->set('isRemoteEnabled',false);
    $options->set('isPhpEnabled',false);
    $options->set('isJavascriptEnabled',false);
    $options->set('tempDir',sys_get_temp_dir());
    $pdf = new Dompdf\Dompdf($options);
    $pdf->setPaper('A4','landscape');
    $pdf->loadHtml($html,'UTF-8');
    $pdf->render();
    $slug = trim(preg_replace('/[^a-z0-9]+/i','-', $teamName) ?? '', '-');
    $filename = ($slug!==''?'Team-'.$slug:'Team').'-Certificates.pdf';
    header('Cache-Control: private, no-store');
    $pdf->stream($filename,['Attachment'=>true]);
    exit;
}

function az_certificate_download(array $certificate): never {
    $token = az_decrypt($certificate['token_enc']);
    $qr = az_certificate_qr($token);
    $award = az_certificate_award((int)$certificate['event_id'],$certificate['team_name']);
    az_certificate_stream_pdf($certificate,$award,$qr);
}

function az_certificate_download_preview(array $certificate, array $award): never {
    az_certificate_stream_pdf($certificate,$award,az_certificate_qr('',true),true);
}

