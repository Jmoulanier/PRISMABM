<?php
header('Content-Type: application/json; charset=UTF-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
    exit;
}

$name    = trim($_POST['name'] ?? '');
$email   = trim($_POST['email'] ?? '');
$company = trim($_POST['company'] ?? '');
$message = trim($_POST['message'] ?? '');
$honeypot = trim($_POST['website'] ?? '');

// honeypot: bots fill this hidden field, humans never see it
if ($honeypot !== '') {
    echo json_encode(['ok' => true]);
    exit;
}

if ($name === '' || $message === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'invalid_input']);
    exit;
}

$to      = 'ventas@prismabm.com';
$subject = '=?UTF-8?B?' . base64_encode('Nuevo contacto desde prismabm.com - ' . $name) . '?=';

$body  = "Nombre: $name\n";
$body .= "Correo: $email\n";
$body .= 'Empresa: ' . ($company !== '' ? $company : '-') . "\n\n";
$body .= "Mensaje:\n$message\n";

// strip CR/LF from header-bound values to prevent header injection
$safeEmail = str_replace(["\r", "\n"], '', $email);
$safeName  = str_replace(["\r", "\n"], '', $name);

$headers   = "From: Prisma BM Web <no-reply@prismabm.com>\r\n";
$headers  .= "Reply-To: \"$safeName\" <$safeEmail>\r\n";
$headers  .= "Content-Type: text/plain; charset=UTF-8\r\n";

$sent = mail($to, $subject, $body, $headers);

if ($sent) {
    echo json_encode(['ok' => true]);
} else {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'send_failed']);
}
