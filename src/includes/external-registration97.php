<?php
declare(strict_types=1);

/** Only responder links may become public redirect destinations. */
function az_google_form_url97(mixed $value,string $label='Google Form link'): string {
    if(!is_string($value)||strlen($value)>2048)throw new InvalidArgumentException($label.' must be a Google Forms responder link.');
    $url=trim($value);if($url==='')return '';
    if(preg_match('/[\x00-\x20\x7F]/',$url)||str_contains($url,'\\')||!filter_var($url,FILTER_VALIDATE_URL))throw new InvalidArgumentException($label.' must be a valid HTTPS Google Forms responder link.');
    $parts=parse_url($url);
    if(!$parts||strtolower($parts['scheme']??'')!=='https'||isset($parts['user'])||isset($parts['pass'])||isset($parts['port']))throw new InvalidArgumentException($label.' must be a valid HTTPS Google Forms responder link.');
    $host=strtolower($parts['host']??'');$path=$parts['path']??'';
    $valid=($host==='forms.gle'&&preg_match('#^/[a-zA-Z0-9_-]+/?$#D',$path))
        ||($host==='docs.google.com'&&preg_match('#^/forms/(?:u/\d+/)?d/(?:e/)?[a-zA-Z0-9_-]+/viewform/?$#D',$path));
    if(!$valid)throw new InvalidArgumentException($label.' must use forms.gle or a docs.google.com/forms responder link ending in /viewform. Copy the responder link, rather than the editor link.');
    return $url;
}

/** A game's own form overrides the event default; blank links keep native registration. */
function az_external_registration_url97(array $fields,string $game=''): string {
    $games=az_event_games($fields,false);
    if($games){
        if($game==='')return '';
        $selected=az_selected_game($fields,$game);
        $value=($selected['registration_url']??'')?:($fields['registration_url']??'');
    }else{
        if($game!=='')throw new InvalidArgumentException('This event does not have game choices.');
        $value=$fields['registration_url']??'';
    }
    // Older records can contain other kinds of external URLs. Never redirect to them.
    try{return az_google_form_url97($value);}catch(InvalidArgumentException){return '';}
}

function az_has_external_registration97(array $fields): bool {
    $all=az_event_games($fields,false);
    if(!$all)return az_external_registration_url97($fields)!=='';
    foreach(az_event_games($fields) as $game)if(az_external_registration_url97($fields,$game['id'])!=='')return true;
    return false;
}

function az_require_internal_registration97(array $fields,string $game=''): void {
    if(az_external_registration_url97($fields,$game)!=='')throw new RuntimeException('This registration is collected through the event coordinator’s Google Form. Use the Register button on the event page.');
}
