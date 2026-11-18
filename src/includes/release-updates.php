<?php
declare(strict_types=1);

/** The organiser's new public address; leave individual coordinators' contacts intact. */
function az_update_official_contact73(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='official_contact_73'")->fetchColumn()) return;
    $db->beginTransaction();
    try {
        az_lock($db);
        if($db->query("SELECT value FROM cms_settings WHERE setting_key='official_contact_73'")->fetchColumn()) {$db->commit();return;}
        $site=json_decode($db->query("SELECT value FROM cms_settings WHERE setting_key='site'")->fetchColumn()?:'{}',true)?:[];
        $site['email']=$site['sponsor_email']='info@ccsdu.in';
        cms_put_setting('site',json_encode($site,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR));
        $revision=(int)$db->query("SELECT value FROM cms_settings WHERE setting_key='settings_revision'")->fetchColumn();
        cms_put_setting('settings_revision',(string)($revision+1));
        az_schema_marker($db,'official_contact_73');
        $db->commit();
    } catch(Throwable $error) {if($db->inTransaction())$db->rollBack();throw $error;}
}

/** Move an existing hero film once; future Studio edits, including clearing it, remain authoritative. */
function az_move_home_film(PDO $db): void {
    if ($db->query("SELECT value FROM cms_settings WHERE setting_key='home_film_location_58'")->fetchColumn()) return;
    $db->beginTransaction();
    try {
        az_lock($db);
        if ($db->query("SELECT value FROM cms_settings WHERE setting_key='home_film_location_58'")->fetchColumn()) {
            $db->commit(); return;
        }
        $saved = $db->query("SELECT value FROM cms_settings WHERE setting_key='site'")->fetchColumn();
        $site = json_decode($saved ?: '{}', true) ?: [];
        if (trim($site['intro_video'] ?? '') === '' && trim($site['intro_video_url'] ?? '') === '') {
            $site['intro_video'] = $site['hero_video'] ?? '/assets/2026/hero-sound.mp4';
            $site['intro_video_poster'] = $site['hero_poster'] ?? '/assets/2026/hero-poster.jpg';
            $site['intro_video_autoplay'] = '1';
            $site['intro_video_controls'] = '1';
            $site['intro_video_loop'] = '1';
            cms_put_setting('site', json_encode($site, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
            $revision = (int)$db->query("SELECT value FROM cms_settings WHERE setting_key='settings_revision'")->fetchColumn();
            cms_put_setting('settings_revision', (string)($revision + 1));
        }
        az_schema_marker($db, 'home_film_location_58');
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        throw $error;
    }
}

/** Add confirmed programme requirements without replacing saved custom forms or historical answers. */
function az_apply_launch_updates(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='launch_forms_52'")->fetchColumn())return;
    $db->beginTransaction();
    try{
        az_lock($db);
        foreach($db->query("SELECT id,slug,data FROM cms_content WHERE type='event'")->fetchAll() as $record){
            $fields=json_decode($record['data'],true)?:[];
            if($record['slug']==='treasure-hunt'){
                foreach(['registration','interest'] as $phase){
                    $form=az_registration_fields($fields,$phase);$labels=array_map('mb_strtolower',array_column($form,'label'));$ids=array_column($form,'id');
                    foreach([
                        ['id'=>'team-name','label'=>'Team name','type'=>'text','required'=>true,'options'=>[]],
                        ['id'=>'issued-team-id','label'=>'Issued team ID','type'=>'text','required'=>true,'options'=>[],'help'=>'Enter the ID supplied by the Treasure Hunt organisers.','placeholder'=>'Your issued ID'],
                    ] as $field)if(!in_array($field['id'],$ids,true)&&!in_array(mb_strtolower($field['label']),$labels,true))$form[]=$field;
                    $fields[$phase==='interest'?'interest_form':'registration_form']=json_encode($form,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
                }
            }
            if($record['slug']==='joystick'){
                $games=az_event_games($fields,false);
                if(!array_filter($games,fn($game)=>str_contains(mb_strtolower($game['label']),'bgmi')||$game['id']==='bgmi'))$games[]=['id'=>'bgmi','label'=>'BGMI','active'=>true];
                $fields['game_categories']=json_encode($games,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
            }
            $db->prepare('UPDATE cms_content SET data=?,revision=revision+1 WHERE id=?')->execute([json_encode($fields,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),$record['id']]);
        }
        az_schema_marker($db,'launch_forms_52');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

/** Preserve event IDs, assignments and financial history when the programme changes. */
function az_apply_programme_updates(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='programme_release_43'")->fetchColumn())return;
    $db->beginTransaction();
    try{
        az_lock($db);
        $query=$db->query("SELECT * FROM cms_content WHERE type='event' AND slug='futsal'");$old=$query->fetch();
        $exists=$db->query("SELECT id FROM cms_content WHERE type='event' AND slug='treasure-hunt'")->fetchColumn();
        if($old&&!$exists){
            $programme=require __DIR__.'/../config/festival.php';$fields=json_decode($old['data'],true)?:[];
            $fields=array_replace($fields,$programme['events']['treasure-hunt']);unset($fields['title']);
            // Old application and ticket snapshots keep their original event name.
            $db->prepare("UPDATE cms_content SET slug='treasure-hunt',title='Treasure Hunt',data=?,revision=revision+1,updated_at=? WHERE id=?")->execute([json_encode($fields,JSON_UNESCAPED_UNICODE),gmdate('c'),$old['id']]);
        }
        $query=$db->query("SELECT id,data FROM cms_content WHERE type='event' AND slug='joystick'");$joystick=$query->fetch();
        if($joystick){
            $fields=json_decode($joystick['data'],true)?:[];
            if(!isset($fields['game_categories'])){
                $fields['game_categories']=json_encode([['id'=>'mobile-legends','label'=>'Mobile Legends','active'=>true]]);
                $db->prepare('UPDATE cms_content SET data=?,revision=revision+1 WHERE id=?')->execute([json_encode($fields,JSON_UNESCAPED_UNICODE),$joystick['id']]);
            }
        }
        // This exact starting visitor count was a presentation fixture, not recorded traffic.
        $db->exec('UPDATE visitors SET count=0 WHERE count=15847');
        az_schema_marker($db,'programme_release_43');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}

/** Remove the old display counter and refresh legacy event metadata without deleting applications. */
function az_clean_public_seed(PDO $db): void {
    if($db->query("SELECT value FROM cms_settings WHERE setting_key='public_data_release_43'")->fetchColumn())return;
    $db->beginTransaction();
    try{
        az_lock($db);
        $db->exec('UPDATE visitors SET count=count-15847 WHERE count>=15847');
        $legacy=$db->query("SELECT id FROM events WHERE slug='futsal'")->fetchColumn();
        if($legacy&&!$db->query("SELECT id FROM events WHERE slug='treasure-hunt'")->fetchColumn())$db->prepare("UPDATE events SET slug='treasure-hunt' WHERE id=?")->execute([$legacy]);
        foreach($db->query("SELECT slug,title,data,status FROM cms_content WHERE type='event'")->fetchAll() as $event){
            $fields=json_decode($event['data'],true)?:[];
            $query=$db->prepare('SELECT id FROM events WHERE slug=?');$query->execute([$event['slug']]);$id=$query->fetchColumn();
            $values=[$event['title'],$fields['short']??'',$fields['description']??'',$fields['starts_at']??'',$fields['registration_closes']??'',$fields['venue']??'', $fields['image']??'',$fields['registration_fee']??'0',$fields['contact']??'',$event['status']==='PUBLISHED'?'ACTIVE':'INACTIVE'];
            if($id){$values[]=$id;$db->prepare('UPDATE events SET title=?,tag_line=?,description=?,event_date=?,last_reg_date=?,location=?,img=?,registration_fees=?,coordinator_details=?,status=?,prizepool=0 WHERE id=?')->execute($values);}
            else{$values[]=$event['slug'];$db->prepare('INSERT INTO events(title,tag_line,description,event_date,last_reg_date,location,img,registration_fees,coordinator_details,status,slug) VALUES(?,?,?,?,?,?,?,?,?,?,?)')->execute($values);}
        }
        az_schema_marker($db,'public_data_release_43');$db->commit();
    }catch(Throwable $error){if($db->inTransaction())$db->rollBack();throw $error;}
}
