<?php
require_once __DIR__.'/../includes/commerce.php';set_security_headers();header('Content-Type: application/json');header('Cache-Control: no-store');
try{
    if($_SERVER['REQUEST_METHOD']!=='POST')throw new RuntimeException('Use POST.');az_csrf();$staff=cms_user();
    if(!$staff||$staff['must_change_password'])throw new RuntimeException('Sign in to Studio.');
    $module=cms_text('module',30);$kind=cms_text('kind',10);$id=(int)($_POST['id']??0);$record=$id?cms_record($id):null;
    if(!in_array($kind,['image','video','audio','pdf'],true)||($module!=='settings'&&!isset(cms_content_schema()[$module])))throw new RuntimeException('Choose a supported upload field.');
    if(($id&&(!$record||$record['type']!==$module))||!cms_can($staff,$module,'edit',$record))throw new RuntimeException('No access to edit this content.');
    $file=$_FILES['file']??[];
    if(($file['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_OK||!is_uploaded_file($file['tmp_name']??''))throw new RuntimeException('Choose a file within the server upload limit.');
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    if(!($kind==='pdf'?$mime==='application/pdf':str_starts_with($mime,$kind.'/')))throw new RuntimeException('Choose a '.$kind.' file for this field.');
    $id=cms_upload($staff,$file);$q=cms_db()->prepare('SELECT path,title,mime FROM cms_media WHERE id=?');$q->execute([$id]);echo json_encode(['ok'=>true,'media'=>$q->fetch()]);
}catch(Throwable $error){http_response_code(400);echo json_encode(['ok'=>false,'error'=>$error instanceof PDOException?'Upload unavailable.':$error->getMessage()]);}
