<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

// --- rozpoznani schematu podle prefixu a delky ---
Assert::same('Visa', SensitiveDataSanitizer::detectCardScheme('4111111111111111'));
Assert::same('Visa', SensitiveDataSanitizer::detectCardScheme('4012888888881881'));
Assert::same('MasterCard', SensitiveDataSanitizer::detectCardScheme('5555555555554444'));
Assert::same('MasterCard', SensitiveDataSanitizer::detectCardScheme('2223003122003222'), 'dvojkova rada z roku 2017');
Assert::same('Amex', SensitiveDataSanitizer::detectCardScheme('378282246310005'));
Assert::same('Discover', SensitiveDataSanitizer::detectCardScheme('6011111111111117'));
Assert::same('DinersClub', SensitiveDataSanitizer::detectCardScheme('30569309025904'));
Assert::same('JCB', SensitiveDataSanitizer::detectCardScheme('3530111333300000'));
Assert::same('UnionPay', SensitiveDataSanitizer::detectCardScheme('6200000000000005'));

// --- co schema nema ---
Assert::null(SensitiveDataSanitizer::detectCardScheme('20260831054055'), 'casova znacka');
Assert::null(SensitiveDataSanitizer::detectCardScheme('2680001586'), 'variabilni symbol');
Assert::null(SensitiveDataSanitizer::detectCardScheme('8590123456789'), 'EAN-13');

// --- listener: dostane schema a delku, NIKDY hodnotu ---
$detected = [];
$s = (new SensitiveDataSanitizer())
	->onCardNumberDetected(function (string $scheme, int $length) use (&$detected): void {
		$detected[] = "$scheme/$length";
	});

$s->sanitize(['receipt' => 'VISA 4111111111111111 schvaleno']);
Assert::same(['Visa/16'], $detected);

// maskovani probehne bez ohledu na listener
Assert::same(['receipt' => 'VISA ************1111 schvaleno'], $s->sanitize(['receipt' => 'VISA 4111111111111111 schvaleno']));

// --- cislo bez znameho prefixu se ZAMASKUJE, ale neupozorni ---
// (siroke maskovani je zamer: seznam prefixu stara a falesne negativni
//  shoda je u sanitizeru drazsi nez falesne pozitivni)
$detected = [];
$s2 = (new SensitiveDataSanitizer())
	->onCardNumberDetected(function (string $scheme, int $length) use (&$detected): void {
		$detected[] = $scheme;
	});
$neznamy = '9999999999999995';   // projde Luhnem, zadne schema
Assert::true(str_contains((string) $s2->sanitize($neznamy), '*'), 'maskuje se');
Assert::same([], $detected, 'ale neupozornuje - nizka jistota');

// --- listener dostane cestu ke klici, aby slo nalez dohledat ---
$paths = [];
$s3 = (new SensitiveDataSanitizer())
	->onCardNumberDetected(function (string $scheme, int $length, string $path) use (&$paths): void {
		$paths[] = $path;
	});
$s3->sanitize(['products' => [['ean' => '8590123456789'], ['ean' => '30569309025904']]]);
Assert::same(['products[1].ean'], $paths, 'vnorene pole i index');

$paths = [];
$s3->sanitize(['response' => ['MaskedPAN' => '************3035', 'PAN' => '4111111111111111']]);
Assert::same(['response.PAN'], $paths, 'i pod karetnim klicem');

$paths = [];
$s3->sanitize('VISA 4111111111111111');
Assert::same([''], $paths, 'holy retezec nema cestu');

$paths = [];
$s3->sanitizeJson('{"a":{"b":"4111111111111111"}}');
Assert::same(['a.b'], $paths, 'JSON se prochazi stejne');

$paths = [];
$s3->sanitizeHeaders(['X-Card' => '4111111111111111']);
Assert::same(['X-Card'], $paths, 'u hlavicek nazev hlavicky');

// klic posila klient - v ceste nesmi uniknout PAN ani registrovane tajemstvi
$paths = [];
$s3->hideValue('zakaznik-abc-xyz');
$s3->sanitize(['4111111111111111' => ['zakaznik-abc-xyz' => '5555555555554444']]);
Assert::same(['[***].***'], $paths, 'ciselny klic PHP prevede na int, proto index');

// listener se dvema parametry funguje dal
$detected = [];
(new SensitiveDataSanitizer())
	->onCardNumberDetected(function (string $scheme, int $length) use (&$detected): void {
		$detected[] = $scheme;
	})
	->sanitize(['x' => '4111111111111111']);
Assert::same(['Visa'], $detected);
