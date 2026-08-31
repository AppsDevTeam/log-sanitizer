<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

$s = new SensitiveDataSanitizer();

// --- neplatne UTF-8 by rozbilo json_encode pri zapisu logu ---
$invalid = "platba \xB1\x31 prijata";
Assert::false(mb_check_encoding($invalid, 'UTF-8'));
$clean = $s->sanitize($invalid);
Assert::true(mb_check_encoding($clean, 'UTF-8'), 'po ocisteni musi byt ulozitelne');
Assert::notSame(false, json_encode(['x' => $clean]), 'a serializovatelne do JSONu');

// --- ridici znaky pryc, tisknutelne zustavaji ---
Assert::same('abcdef', $s->sanitize("ab\x00cd\x07ef"));
Assert::same("radek1\nradek2", $s->sanitize("radek1\nradek2"), 'novy radek se zachova');
Assert::same("a\tb", $s->sanitize("a\tb"), 'tabulator se zachova');

// --- dlouhy base64 (obrazek, priloha) se nahradi hashem ---
$image = base64_encode(random_bytes(400));
$result = $s->sanitize($image);
Assert::match('md5:%h%', $result);
Assert::same('md5:' . md5($image), $result, 'stejny vstup da stejny hash - jde porovnat vyskyt');

// kratky base64 se nechava, at se neztrati bezna data
$shortBase64 = base64_encode('ahoj');
Assert::same($shortBase64, $s->sanitize($shortBase64));

// dlouhy text, ktery base64 neni, zustava
$text = str_repeat('bezny dlouhy text s mezerami. ', 20);
Assert::same($text, $s->sanitize($text));

// --- diakritika se neposkodi ---
Assert::same('žluťoucký kůň úpěl ďábelské ódy', $s->sanitize('žluťoucký kůň úpěl ďábelské ódy'));
