<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

$s = new SensitiveDataSanitizer();

/**
 * Skutecna odpoved platebniho terminalu (uzaverka) z transaction_log.
 * Regresni test na vec, ktera se na tomhle payloadu ukazala: casova znacka
 * ve formatu YmdHis ma 14 cislic a Luhnem projde kazda desata, takze samotny
 * Luhn ji v desetine pripadu zamaskoval.
 */
$payload = [
	'TransactionID' => 'df4489e9-59c5-4a0d-b05d-2ef7148bea22',
	'InvNumber' => '',
	'Response' => '0',
	'Result' => '0',
	'HostTransID' => '',
	'RespMessage' => 'Soucty souhlasi',
	'HostRC' => 7,
	'TransactionTime' => '20250101001342',   // tenhle konkretni Luhnem PROJDE
	'AmountAuthorized' => '0.00 CZK',
	'CurrencyCode' => 'CZK',
	'Signature' => 'N',
	'BIN' => '',
	'Tokenization' => [],
	'MerchantReceipt' => '<center>TEST4342(M1TEST4342-53267815)</center><center>Uzávěrka</center>',
];

$out = $s->sanitize($payload);

// --- provozni data zustavaji nedotcena ---
Assert::same($payload['TransactionID'], $out['TransactionID']);
Assert::same($payload['TransactionTime'], $out['TransactionTime'], 'casova znacka se nesmi maskovat');
Assert::same($payload['AmountAuthorized'], $out['AmountAuthorized']);
Assert::same($payload['MerchantReceipt'], $out['MerchantReceipt']);
Assert::same(7, $out['HostRC']);

// --- prazdna hodnota se nemaskuje: skryt neni co ---
Assert::same([], $out['Tokenization'], 'v logu ma zustat videt, ze pole bylo prazdne');
Assert::same('', $out['BIN']);

// --- ale neprazdna tokenizace uz ano ---
$withToken = $s->sanitize(['Tokenization' => ['token' => 'abcdef1234567890']]);
Assert::same(SensitiveDataSanitizer::MASK, $withToken['Tokenization']);

// --- casove znacky obecne ---
Assert::same('20250909095540', $s->sanitize('20250909095540'), 'YmdHis');
Assert::same('20251231235959', $s->sanitize('20251231235959'), 'YmdHis, Luhn projde');
Assert::same('1757404540123', $s->sanitize('1757404540123'), 'unix v milisekundach');

// --- a naopak: cislo karty uprostred uctenky se zamaskovat MUSI ---
$receipt = '<left>VISA</left><center>4111111111111111</center><right>61,00 CZK</right>';
Assert::same(
	'<left>VISA</left><center>************1111</center><right>61,00 CZK</right>',
	$s->sanitize($receipt),
);

// jiz maskovany PAN z terminalu zustava, jak prisel
$masked = '<center>************1111</center>';
Assert::same($masked, $s->sanitize($masked));
