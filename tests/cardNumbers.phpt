<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

$s = new SensitiveDataSanitizer();

// --- testovaci cisla karet (verejne testovaci sady, projdou Luhnem) ---
Assert::same('************1111', $s->sanitize('4111111111111111'), 'Visa 16');
Assert::same('***********0005', $s->sanitize('378282246310005'), 'Amex 15');
Assert::same('**********5904', $s->sanitize('30569309025904'), 'Diners 14');

// oddelovace se rozpoznaji a cislo zmizi cele
Assert::same('************1111', $s->sanitize('4111 1111 1111 1111'));
Assert::same('************1111', $s->sanitize('4111-1111-1111-1111'));

// uprostred textu
Assert::same(
	'platba kartou ************1111 zamitnuta',
	$s->sanitize('platba kartou 4111111111111111 zamitnuta'),
);

// ve strukture pod nevinnym klicem - proto to hleda v hodnotach, ne jen v klicich
Assert::same(
	['note' => '************1111'],
	$s->sanitize(['note' => '4111111111111111']),
);

// --- co se maskovat NESMI: cisla, ktera Luhnem neprojdou ---
Assert::same('1234567890123456', $s->sanitize('1234567890123456'), 'neni platny Luhn');
Assert::same('objednavka 20260831000123', $s->sanitize('objednavka 20260831000123'));
Assert::same('8590123456789', $s->sanitize('8590123456789'), 'EAN-13');

// --- UUID: hex s pomlckami splyne v kandidata a kazdy desaty projde Luhnem ---
// d5018957-3288-49bb -> 5018957328849: 13 cislic, platny Luhn, prefix 5018 = Maestro
$uuid = 'd5018957-3288-49bb-8e98-f1cb15ad8d71';
Assert::same($uuid, $s->sanitize($uuid), 'UUID se nesmi zamaskovat');
Assert::same(
	['TransactionID' => $uuid],
	$s->sanitize(['TransactionID' => $uuid]),
);
Assert::same("transakce $uuid zamitnuta", $s->sanitize("transakce $uuid zamitnuta"));

// upozorneni na nemaskovany PAN se u UUID nesmi vystrelit
$alerts = [];
$listening = (new SensitiveDataSanitizer())
	->onCardNumberDetected(function (string $scheme, int $length) use (&$alerts): void {
		$alerts[] = [$scheme, $length];
	});
Assert::same($uuid, $listening->sanitize($uuid));
Assert::same([], $alerts, 'zadny plany poplach');

// skutecny PAN vedle UUID se zamaskovat MUSI - zamitnuty kandidat konci
// uprostred PANu, takze se nesmi preskocit cely
Assert::same("$uuid ************1111", $s->sanitize("$uuid 4111111111111111"));
Assert::same("************1111 $uuid", $s->sanitize("4111111111111111 $uuid"));

// --- kratka a dlouha cisla mimo rozsah PAN ---
Assert::same('123456789012', $s->sanitize('123456789012'), '12 cislic je pod hranici');
Assert::same('12345678901234567890', $s->sanitize('12345678901234567890'), '20 cislic je nad hranici');

// --- vypnuti ---
$off = (new SensitiveDataSanitizer())->withoutCardNumberMasking();
Assert::same('4111111111111111', $off->sanitize('4111111111111111'));
