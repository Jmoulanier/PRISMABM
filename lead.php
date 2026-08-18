<?php
header('Content-Type: application/json; charset=UTF-8');

// Destino de los leads. Cuando IT cree ventas@prismabm.com como alias en
// Microsoft 365, cambiar esta linea a 'ventas@prismabm.com'.
$to = 'pablo.bravo@prismabm.com';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
    exit;
}

// rate limit simple por IP: max 5 envios por hora
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rlFile = dirname(__DIR__) . '/contact_ratelimit.json';
$now = time();
$rl = [];
if (is_file($rlFile)) {
    $rl = json_decode(file_get_contents($rlFile), true) ?: [];
}
// purga entradas viejas
foreach ($rl as $k => $times) {
    $rl[$k] = array_values(array_filter($times, fn($t) => $now - $t < 3600));
    if (!$rl[$k]) unset($rl[$k]);
}
if (count($rl[$ip] ?? []) >= 5) {
    http_response_code(429);
    echo json_encode(['ok' => false, 'error' => 'too_many_requests']);
    exit;
}

$name     = trim($_POST['name'] ?? '');
$email    = trim($_POST['email'] ?? '');
$company  = trim($_POST['company'] ?? '');
$message  = trim($_POST['message'] ?? '');
$honeypot = trim($_POST['website'] ?? '');

// honeypot: bots fill this hidden field, humans never see it
if ($honeypot !== '') {
    echo json_encode(['ok' => true]);
    exit;
}

// limites de longitud
if (strlen($name) > 100 || strlen($email) > 254 || strlen($company) > 150 || strlen($message) > 5000) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'invalid_input']);
    exit;
}

if ($name === '' || $message === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'invalid_input']);
    exit;
}

$subject = '=?UTF-8?B?' . base64_encode('Nuevo contacto desde prismabm.com - ' . $name) . '?=';

$body  = "Nombre: $name\n";
$body .= "Correo: $email\n";
$body .= 'Empresa: ' . ($company !== '' ? $company : '-') . "\n\n";
$body .= "Mensaje:\n$message\n";

// strip CR/LF from header-bound values to prevent header injection
$safeEmail = str_replace(["\r", "\n"], '', $email);
$safeName  = str_replace(["\r", "\n"], '', $name);

// From debe ser del propio dominio para alinear con SPF (la IP del servidor
// ya esta autorizada en el registro SPF de prismabm.com).
$headers  = "From: Prisma BM Web <no-reply@prismabm.com>\r\n";
$headers .= "Reply-To: \"$safeName\" <$safeEmail>\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

$sent = mail($to, $subject, $body, $headers, '-f no-reply@prismabm.com');

if ($sent) {
    $rl[$ip][] = $now;
    file_put_contents($rlFile, json_encode($rl), LOCK_EX);
    echo json_encode(['ok' => true]);
} else {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'send_failed']);
}
