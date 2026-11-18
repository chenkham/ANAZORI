<?php
declare(strict_types=1);

const ANAZORI_MAILBOX='noreply@ccsdu.in';

function az_mail_escape(string $text): string {return htmlspecialchars($text,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}

/** Inline tables, readable fallbacks and the same violet/pearl identity as the site. */
function az_mail_template(string $kind,array $data): array {
    $messages=[
        'verify'=>['Verify your email','One code. Your way in.','Enter the code below on the website to verify your email address.','EMAIL VERIFICATION'],
        'reset'=>['Reset your password',"Let's get you back in.",'Enter this code on the website to choose a new password.','PASSWORD RESET'],
        'registration_received'=>['Your ANAZORI registration is received','Your registration is with the event team.','Your submission has been saved and is awaiting review. This email is an acknowledgement, not an approval or entry ticket. We will email you again when your ticket is approved.','SUBMITTED'],
        'ticket_confirmed'=>['Your ANAZORI ticket is ready','Your place is confirmed.','Your registration has been approved. Your ticket is ready in My festival. Keep it available for entry and check the event details below.','APPROVED'],
        'ticket_rejected'=>['Registration not approved','An update from your event team.','The event team has not approved this registration. Please read their reason below and contact the coordinators if you need help.','NOT APPROVED'],
        'event_reminder'=>['Your ANAZORI event is coming up',"It's almost time.",'Your event is coming up. Check the confirmed start time and venue, and keep your approved ticket ready for entry.','EVENT REMINDER'],
    ];
    if(!isset($messages[$kind]))throw new InvalidArgumentException('Unknown email template.');
    [$subject,$title,$intro,$badge]=$messages[$kind];
    if($kind==='ticket_rejected'&&($data['rejection_type']??'')==='payment'){
        $title='Your payment details need an update.';
        $intro='The event team could not approve your payment evidence. Your ticket is waiting for corrected details. Read their note, then open your registration to make the requested update.';
    }
    if($kind==='ticket_rejected'&&($data['rejection_type']??'')==='ticket'){
        $subject='Your ANAZORI ticket status changed';$title='Please review your ticket status.';$badge='TICKET ON HOLD';
        $intro='The event team has put this ticket on hold. It cannot be used for entry while blocked. Read their reason below and contact the coordinators through the event page.';
    }
    $event=trim(preg_replace('/[\r\n]+/',' ',(string)($data['event']??'')));
    if($event!==''&&!in_array($kind,['verify','reset'],true))$subject.=' | '.$event;
    $name=trim((string)($data['name']??''));$greeting=$name!==''?'Hi '.$name.',':'Hello,';
    $escape='az_mail_escape';$origin=rtrim(az_origin(),'/');$code=(string)($data['code']??'');$otp=in_array($kind,['verify','reset'],true);
    if($otp&&!preg_match('/^\d{6}$/D',$code))throw new InvalidArgumentException('Invalid email code.');
    if(!$otp&&$code!=='')throw new InvalidArgumentException('Unexpected email code.');
    $rows=[];
    foreach(['event'=>'Event','game'=>'Game','category'=>'Ticket category','people'=>'People covered','when'=>'Date & time','venue'=>'Venue','reference'=>'Registration reference','ticket'=>'Ticket ID'] as $key=>$label){
        $value=trim((string)($data[$key]??''));if($value!=='')$rows[$label]=$value;
    }
    $plain=$greeting."\n\n".$title."\n\n".$intro."\n\n";$details='';
    foreach($rows as $label=>$value){
        $details.='<tr><td width="34%" valign="top" style="padding:12px 16px;border-bottom:1px solid #d4c3e5;font-size:12px;line-height:20px;color:#6c557e">'.$escape($label).'</td><td valign="top" style="padding:12px 16px;border-bottom:1px solid #d4c3e5;font-size:14px;line-height:21px;font-weight:bold;color:#30213f;overflow-wrap:anywhere;word-break:break-word">'.$escape($value).'</td></tr>';
        $plain.=$label.': '.$value."\n";
    }
    $codeHtml='';
    if($otp){
        $codeHtml='<table role="presentation" width="100%" cellspacing="0" cellpadding="0" bgcolor="#eee2fb" style="margin:22px 0;border:1px solid #c9a8e8;border-radius:12px"><tr><td align="center" style="padding:24px 10px;font-family:Consolas,monospace;font-size:36px;line-height:44px;font-weight:bold;letter-spacing:7px;color:#30213f">'.$code.'</td></tr></table><p style="margin:0 0 8px;font-size:13px;line-height:22px;color:#d7c5e8">Valid for <strong style="color:#ffffff">10 minutes</strong>. Use it once and keep it private.</p>';
        $plain.='Your ANAZORI code: '.$code."\nExpires in 10 minutes. Use it once. Never share this code.\n\n";
    }
    $note=trim((string)($data['note']??''));$noteHtml='';
    if(!$otp&&$note!==''){
        $noteHtml='<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:20px;border:1px solid #76516d;border-left:4px solid #efa2c8;background:#2c1b2c;border-radius:8px"><tr><td style="padding:17px 18px;color:#f5e9f5;font-size:14px;line-height:23px;overflow-wrap:anywhere"><div style="margin-bottom:6px;font-size:10px;font-weight:bold;letter-spacing:1.5px;color:#f4b3d3">FROM YOUR COORDINATOR</div>'.nl2br($escape($note)).'</td></tr></table>';
        $plain.="\nCoordinator note:\n".$note."\n";
    }
    $button='';
    if(!$otp){
        $path=(string)($data['path']??'/dashboard.php');
        if(!preg_match('#^/(?:dashboard\.php|payment-proof\.php\?order=ORDER-[A-F0-9]{16}|ticket\.php\?id=AZ16-[A-F0-9]{14}|event\.php\?name=[a-z0-9-]+)$#D',$path))throw new InvalidArgumentException('Invalid email action.');
        $url=$origin.$path;$cta=(string)($data['cta']??'Open My festival');
        $button='<table role="presentation" cellspacing="0" cellpadding="0" style="margin:24px 0 16px"><tr><td bgcolor="#c49be8" style="border-radius:8px;border:1px solid #e0c7f3"><a href="'.$escape($url).'" style="display:inline-block;padding:15px 23px;font-size:14px;line-height:20px;font-weight:bold;text-decoration:none;color:#281638">'.$escape($cta).'</a></td></tr></table><p style="margin:0;font-size:11px;line-height:19px;color:#bda8d0;overflow-wrap:anywhere;word-break:break-word">Or open this secure link:<br><a href="'.$escape($url).'" style="color:#ddbef5;text-decoration:underline">'.$escape($url).'</a></p>';
        $plain.="\n".$cta.': '.$url."\n";
    }
    $helpPath=(string)($data['event_path']??'/events.php');
    if(!preg_match('#^/(?:events\.php|event\.php\?name=[a-z0-9-]+)$#D',$helpPath))$helpPath='/events.php';
    $footer=$otp?'If you did not request this code, ignore this email. Your account will not change.':'Need help? Contact your event coordinators through the event page. This message is sent automatically; replies are not monitored.';
    $plain.="\n".$footer."\nANAZORI | CCSA, Dibrugarh University";
    $accent=$kind==='ticket_rejected'?'#efa2c8':'#a9d9d1';
    $html='<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>'.$escape($subject).'</title><style>@media only screen and (max-width:520px){.mail-pad{padding:22px 20px!important}.mail-title{font-size:28px!important;line-height:35px!important}.mail-brand{width:220px!important;height:auto!important}}</style></head><body style="margin:0;padding:0;background:#0c0912;font-family:Arial,Helvetica,sans-serif;-webkit-text-size-adjust:100%"><div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all">'.$escape($intro).'</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" bgcolor="#0c0912"><tr><td align="center" style="padding:28px 12px"><table role="presentation" width="600" cellspacing="0" cellpadding="0" bgcolor="#1a1126" style="width:100%;max-width:600px;border:1px solid #49315e;border-radius:14px;overflow:hidden"><tr><td><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td width="55%" height="4" bgcolor="#b28bde" style="font-size:1px;line-height:4px">&nbsp;</td><td width="30%" height="4" bgcolor="#efa2c8" style="font-size:1px;line-height:4px">&nbsp;</td><td width="15%" height="4" bgcolor="#82d5d7" style="font-size:1px;line-height:4px">&nbsp;</td></tr></table></td></tr><tr><td class="mail-pad" style="padding:27px 28px 23px;border-bottom:1px solid #49315e"><img class="mail-brand" src="'.$escape($origin.'/assets/2026/email-wordmark101.png').'" width="242" height="56" alt="ANAZORI V16.0" style="display:block;width:242px;height:56px;border:0;color:#e4c6ff;font-size:25px;font-weight:bold"><p style="margin:11px 0 0;font-size:9px;line-height:15px;letter-spacing:1.7px;color:#c4b2d5">CULTURE &times; TECH &nbsp; / &nbsp; CCSA, DIBRUGARH UNIVERSITY</p></td></tr><tr><td class="mail-pad" style="padding:27px 28px 30px"><p style="margin:0 0 17px;font-size:10px;line-height:17px;letter-spacing:1.8px;font-weight:bold;color:'.$accent.'">'.$escape($badge).'</p><p style="margin:0 0 10px;font-size:14px;line-height:22px;color:#d1bddf">'.$escape($greeting).'</p><h1 class="mail-title" style="margin:0 0 17px;font-size:34px;line-height:41px;letter-spacing:-1px;font-weight:bold;color:#f6edff">'.$escape($title).'</h1><p style="margin:0 0 22px;font-size:15px;line-height:25px;color:#dfcfe9">'.$escape($intro).'</p>'.$codeHtml.($details!==''?'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" bgcolor="#eee4f6" style="border:1px solid #d4c3e5;border-radius:10px;overflow:hidden">'.$details.'</table>':'').$noteHtml.$button.'</td></tr><tr><td class="mail-pad" bgcolor="#130c1c" style="padding:21px 28px;border-top:1px solid #49315e"><p style="margin:0 0 12px;font-size:11px;line-height:19px;color:#bfaccf">'.$escape($footer).'</p>'.(!$otp?'<p style="margin:0 0 14px;font-size:11px;line-height:18px"><a href="'.$escape($origin.$helpPath).'" style="color:#dfc4f4;text-decoration:underline">Contact the event team</a></p>':'').'<p style="margin:0;font-size:10px;line-height:18px;color:#9f88b2">ANAZORI &middot; CCSA, Dibrugarh University<br><a href="'.$escape($origin.'/privacy.php').'" style="color:#bfa6d2;text-decoration:underline">Privacy</a> &nbsp;&middot;&nbsp; <a href="'.$escape($origin.'/terms.php').'" style="color:#bfa6d2;text-decoration:underline">Terms</a></p></td></tr></table></td></tr></table></body></html>';
    return ['subject'=>$subject,'body'=>$plain,'html'=>$html];
}

function az_mail_event_time(string $value): string {
    if($value==='')return '';
    try{return (new DateTimeImmutable($value,new DateTimeZone('Asia/Kolkata')))->setTimezone(new DateTimeZone('Asia/Kolkata'))->format('D, j M Y, g:i A').' IST';}
    catch(Throwable){return '';}
}
