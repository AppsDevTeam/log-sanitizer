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

// --- zalomeny base64 (MIME po 76, PEM po 64 znacich) taky ---
foreach ([76 => "\n", 64 => "\r\n"] as $width => $eol) {
	$wrapped = chunk_split($image, $width, $eol);
	Assert::same('md5:' . md5($wrapped), $s->sanitize($wrapped), "zalomeni po $width");
	Assert::same('md5:' . md5(rtrim($wrapped)), $s->sanitize(rtrim($wrapped)), "bez koncoveho odradkovani, po $width");
}

// nepravidelne zalomeny text bez mezer za base64 nepovazujeme
$irregular = implode("\n", [str_repeat('abcd', 30), str_repeat('efgh', 20), str_repeat('ijkl', 30)]);
Assert::same($irregular, $s->sanitize($irregular));

// --- data URI: media typ zustane, obsah se nahradi hashem ---
$dataUri = 'data:image/png;base64,' . $image;
Assert::same('data:image/png;base64,md5:' . md5($dataUri), $s->sanitize($dataUri));
$dataUri = 'data:;base64,' . chunk_split($image, 76, "\n");
Assert::same('data:;base64,md5:' . md5($dataUri), $s->sanitize($dataUri), 'bez media typu, zalomeny');
$dataUri = 'data:text/plain;charset=utf-8;base64,' . $image;
Assert::same('data:text/plain;charset=utf-8;base64,md5:' . md5($dataUri), $s->sanitize($dataUri), 's parametrem');

// data URI, jehoz obsah base64 neni, se prohledava dal
$notBase64 = 'data:image/png;base64,' . str_repeat('neni to base64 ', 20) . '4111111111111111';
Assert::contains('************1111', (string) $s->sanitize($notBase64));

// --- SVG dokument se nahradi hashem: souradnice by jinak delaly plane poplachy ---
$alerts = [];
$withListener = (new SensitiveDataSanitizer())
	->onCardNumberDetected(function (string $scheme) use (&$alerts): void {
		$alerts[] = $scheme;
	});
// realny pripad: "-211 23 127 -394 -20 228 126" da MasterCard/16 s platnym Luhnem
$polygon = '<polygon points="310 239 -211 23 127 -394 -20 228 126 -265 68 -381"/>';
$svg = '<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
		<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
		<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800">' . $polygon . '</svg>';
Assert::same(['svg' => 'md5:' . md5($svg)], $withListener->sanitize(['svg' => $svg]));
Assert::same([], $alerts, 'zadny poplach');
Assert::same('md5:' . md5('<svg>' . $polygon . '</svg>'), $withListener->sanitize('<svg>' . $polygon . '</svg>'), 'i bez deklarace');

// fragment ani text, ktery SVG jen obsahuje, dokumentem neni - prohledava se dal
Assert::contains('********', (string) $withListener->sanitize($polygon), 'fragment bez <svg>');
Assert::same(['MasterCard'], $alerts);
Assert::same('karta ************1111 <svg></svg>', $withListener->sanitize('karta 4111 1111 1111 1111 <svg></svg>'), 'text pred <svg>');

// kratky base64 se nechava, at se neztrati bezna data
$shortBase64 = base64_encode('ahoj');
Assert::same($shortBase64, $s->sanitize($shortBase64));

// dlouhy text, ktery base64 neni, zustava
$text = str_repeat('bezny dlouhy text s mezerami. ', 20);
Assert::same($text, $s->sanitize($text));

// --- diakritika se neposkodi ---
Assert::same('žluťoucký kůň úpěl ďábelské ódy', $s->sanitize('žluťoucký kůň úpěl ďábelské ódy'));

// --- ocisti se i NAZEV klice: nevalidni UTF-8 v nem rozbije json_encode
//     uplne stejne jako v hodnote a log by se neulozil vubec ---
$badKey = "na\xB1zev";
$out = $s->sanitize([$badKey => 'hodnota']);
Assert::notSame(false, json_encode($out), 'cely zaznam musi byt serializovatelny');
foreach (array_keys($out) as $k) {
	Assert::true(mb_check_encoding((string) $k, 'UTF-8'));
}

Assert::same(['abc' => 'x'], $s->sanitize(["a\x00b\x07c" => 'x']), 'ridici znaky v klici');
Assert::same(['heslo_pole' => 'x'], $s->sanitize(['heslo_pole' => 'x']), 'bezny klic se nemeni');

// citlivost se posuzuje az po ocisteni klice
Assert::same(['password' => SensitiveDataSanitizer::MASK], $s->sanitize(["pass\x00word" => 'Tajne123']));
