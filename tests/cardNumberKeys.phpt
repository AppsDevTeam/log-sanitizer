<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

const MASK = SensitiveDataSanitizer::MASK;

$s = new SensitiveDataSanitizer();

// --- surove cislo pod karetnim klicem se ZKRATI, ne zahodi ---
Assert::same(['PAN' => '************1111'], $s->sanitize(['PAN' => '4111111111111111']));
Assert::same(['cardNumber' => '************4444'], $s->sanitize(['cardNumber' => '5555555555554444']));
Assert::same(['card_number' => '***********0005'], $s->sanitize(['card_number' => '378282246310005']));

// --- uz zkracene cislo z terminalu zustava, jak prislo ---
// PCI DSS pripousti zkraceni jako metodu, a poslednich ctyr je potreba
// k parovani a reklamacim - pausalni '***' by je znicilo bez zisku
Assert::same(['MaskedPAN' => '************3035'], $s->sanitize(['MaskedPAN' => '************3035']));
Assert::same(['maskedPan' => '000000******3035'], $s->sanitize(['maskedPan' => '000000******3035']));

// --- zachytna sit: cislo, ktere neprojde Luhnem, pod karetnim klicem neprojde ---
Assert::same(['PAN' => MASK], $s->sanitize(['PAN' => '1234567890123456']), 'neplatny Luhn, ale je to PAN klic');
Assert::same(['PAN' => MASK], $s->sanitize(['PAN' => '20250909095540']), 'casova znacka pod PAN klicem taky ne');

// --- s vypnutym maskovanim karet nesmi hodnota projit vubec ---
$off = (new SensitiveDataSanitizer())->withoutCardNumberMasking();
Assert::same(['PAN' => MASK], $off->sanitize(['PAN' => '4111111111111111']));
Assert::same(['MaskedPAN' => MASK], $off->sanitize(['MaskedPAN' => '************3035']));

// --- SAD se maskuje porad pausalne, zkraceni tam nema co delat ---
Assert::same(['cvv' => MASK], $s->sanitize(['cvv' => '123']));
Assert::same(['PINBlock' => MASK], $s->sanitize(['PINBlock' => 'A1B2C3D4E5F60708']));
Assert::same(['track2' => MASK], $s->sanitize(['track2' => '4111111111111111=25121011000012345678']));
