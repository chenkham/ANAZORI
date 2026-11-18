<?php
require_once __DIR__.'/includes/commerce.php';
set_security_headers();
az_payment_proof_file((int)($_GET['id']??0));
