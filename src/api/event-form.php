<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/commerce.php';
set_security_headers();header('Content-Type: application/json; charset=utf-8');header('Cache-Control: private, no-store');
try{
 if(($_SERVER['REQUEST_METHOD']??'')!=='GET')throw new RuntimeException('Use GET.');
 $slug=is_string($_GET['event']??null)?$_GET['event']:'';$game=is_string($_GET['game']??null)?$_GET['game']:'';$phase=$_GET['phase']??'interest';
 if(!in_array($phase,['interest','registration'],true))throw new RuntimeException('Choose a form.');
 $event=az_event($slug);if(!$event)throw new RuntimeException('Event unavailable.');
 az_selected_game($event['fields'],$game);$fields=az_game_fields81($event['fields'],$game,$phase);
 if(!az_form_settings($fields,$phase)['accepting'])throw new RuntimeException('This form is currently closed.');
 ob_start();az_registration_form($fields,$phase);$html=ob_get_clean();echo json_encode(['html'=>$html,'title'=>$fields[$phase.'_title']??'','intro'=>$fields[$phase.'_intro']??'','button'=>$fields[$phase.'_button']??'Submit','game'=>$fields['_form_game_label']??''],JSON_THROW_ON_ERROR);
}catch(Throwable $error){http_response_code(422);echo json_encode(['error'=>$error->getMessage()]);}
