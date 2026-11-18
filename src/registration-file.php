<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
az_serve_registration_file((int)($_GET['id']??0));
