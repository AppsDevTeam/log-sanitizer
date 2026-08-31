<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

const MASK = SensitiveDataSanitizer::MASK;

$s = new SensitiveDataSanitizer();

// --- klic zustava, hodnota mizi ---
Assert::same(
	['email' => 'a@b.cz', 'password' => MASK],
	$s->sanitize(['email' => 'a@b.cz', 'password' => 'Tajne123']),
	'v logu ma zustat videt, ZE pole prislo',
);

// --- rekurze do vnorenych struktur ---
Assert::same(
	['user' => ['name' => 'Jan', 'credentials' => ['token' => MASK]]],
	$s->sanitize(['user' => ['name' => 'Jan', 'credentials' => ['token' => 'abcdef123456']]]),
);

// --- maskuje se cely podstrom pod citlivym klicem ---
Assert::same(
	['secret' => MASK],
	$s->sanitize(['secret' => ['nested' => ['deep' => 'value']]]),
);

// --- seznamy a ciselne klice ---
Assert::same(
	[['pin' => MASK], ['pin' => MASK]],
	$s->sanitize([['pin' => '1234'], ['pin' => '5678']]),
);

// --- neskalarni typy zustavaji beze zmeny ---
Assert::same(
	['count' => 5, 'ratio' => 1.5, 'active' => true, 'missing' => null],
	$s->sanitize(['count' => 5, 'ratio' => 1.5, 'active' => true, 'missing' => null]),
);

// --- stdClass z json_decode bez forceArrays ---
$object = json_decode('{"password":"x123456789","email":"a@b.cz"}');
Assert::same(['password' => MASK, 'email' => 'a@b.cz'], $s->sanitize($object));

// --- prazdne pole neni null ---
Assert::same([], $s->sanitize([]));

// --- JSON dovnitr, JSON zpatky ---
Assert::same(
	'{"email":"a@b.cz","password":"***"}',
	$s->sanitizeJson('{"email":"a@b.cz","password":"Tajne123"}'),
);

// neplatny JSON se ocisti jako text, ne zahodi
Assert::same('nejaky <b>text</b>', $s->sanitizeJson('nejaky <b>text</b>'));
Assert::null($s->sanitizeJson(null));
Assert::same('', $s->sanitizeJson(''));

// diakritika a lomitka se nemaji rozsypat do escapes
Assert::same('{"note":"prilis žluťoucký kůň/úpěl"}', $s->sanitizeJson('{"note":"prilis žluťoucký kůň\/úpěl"}'));
