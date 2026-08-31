<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

$s = new SensitiveDataSanitizer();

$headers = [
	'User-Agent' => 'SobIT/1.0',
	'Content-Type' => 'application/json',
	'Authorization' => 'Basic dXNlcjpwYXNz',
	'X-Api-Key' => 'secret-api-key-value',
	'Cookie' => 'PHPSESSID=abc123',
	'X-Device-Info' => 'android;13;pixel;SN123456',
];

$sanitized = $s->sanitizeHeaders($headers);

// nositele pristupu se do logu nedostanou vubec - jejich pritomnost
// sama o sobe nema diagnostickou hodnotu
Assert::false(array_key_exists('Authorization', $sanitized));
Assert::false(array_key_exists('X-Api-Key', $sanitized));
Assert::false(array_key_exists('Cookie', $sanitized));

// diagnosticky uzitecne zustavaji nedotcene
Assert::same('SobIT/1.0', $sanitized['User-Agent']);
Assert::same('application/json', $sanitized['Content-Type']);
Assert::same('android;13;pixel;SN123456', $sanitized['X-Device-Info']);

// mala i velka pismena v nazvu hlavicky
Assert::same([], $s->sanitizeHeaders(['authorization' => 'x', 'AUTHORIZATION' => 'y']));

// hlavicka, ktera neni v seznamu vyhozenych, ale klic je citlivy -> maskuje se
Assert::same(
	['X-Refresh-Token' => SensitiveDataSanitizer::MASK],
	$s->sanitizeHeaders(['X-Refresh-Token' => 'abcdef1234567890']),
);

// vlastni seznam vyhozenych hlavicek
$custom = new SensitiveDataSanitizer(droppedHeaders: ['x-trace']);
$result = $custom->sanitizeHeaders(['X-Trace' => 'abc', 'Authorization' => 'Basic xxx']);
Assert::false(array_key_exists('X-Trace', $result));
Assert::true(array_key_exists('Authorization', $result), 'vlastni seznam nahrazuje vychozi');
