<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

const MASK = SensitiveDataSanitizer::MASK;

// Scenar, ktery tohle resi: endpoint vraci jednorazovy prihlasovaci token.
// Nazev klice je sice 'token', ale hodnota se muze objevit i jinde - v URL
// odpovedi, v chybove zprave, v nesouvisejicim poli.
$token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

$s = new SensitiveDataSanitizer();
$s->hideValue($token);

Assert::same(['token' => MASK], $s->sanitize(['token' => $token]), 'shoda podle klice');

Assert::same(
	['redirect' => 'https://app.example.com/login?t=' . MASK],
	$s->sanitize(['redirect' => 'https://app.example.com/login?t=' . $token]),
	'tatáz hodnota uprostred textu pod nevinnym klicem',
);

Assert::same(
	['message' => 'Token ' . MASK . ' expired.'],
	$s->sanitize(['message' => 'Token ' . $token . ' expired.']),
);

// --- prilis kratke hodnoty se neregistruji, jinak by zmizel pul logu ---
$short = new SensitiveDataSanitizer();
$short->hideValue('abc');
Assert::same(['note' => 'abc je abeceda'], $short->sanitize(['note' => 'abc je abeceda']));

$short->hideValue(null);
Assert::same(['note' => 'nic se nestalo'], $short->sanitize(['note' => 'nic se nestalo']));

// --- vice tajemstvi zaraz ---
$multi = new SensitiveDataSanitizer();
$multi->hideValue('first-secret-value')->hideValue('second-secret-value');
Assert::same(
	['a' => MASK, 'b' => MASK],
	$multi->sanitize(['a' => 'first-secret-value', 'b' => 'second-secret-value']),
);
