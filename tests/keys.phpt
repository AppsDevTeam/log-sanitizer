<?php

declare(strict_types=1);

use ADT\LogSanitizer\SensitiveDataSanitizer;
use Tester\Assert;

require __DIR__ . '/bootstrap.php';

$s = new SensitiveDataSanitizer();

// --- delsi terminy jako podretezec ---
Assert::true($s->isSensitiveKey('password'));
Assert::true($s->isSensitiveKey('passwordConfirm'), 'camelCase varianta');
Assert::true($s->isSensitiveKey('password_confirmation'), 'snake_case varianta');
Assert::true($s->isSensitiveKey('PASSWORD'), 'case-insensitive');
Assert::true($s->isSensitiveKey('accessToken'));
Assert::true($s->isSensitiveKey('refresh_token'));
Assert::true($s->isSensitiveKey('apiKey'), 'api_key sedi i bez oddelovace');
Assert::true($s->isSensitiveKey('x-api-key'));
Assert::true($s->isSensitiveKey('clientSecret'));

// --- kratke terminy jen na cele slovo ---
Assert::true($s->isSensitiveKey('pin'));
Assert::true($s->isSensitiveKey('card_pin'));
Assert::true($s->isSensitiveKey('pinBlock'));
Assert::true($s->isSensitiveKey('cvv'));

// --- karetni klice NEJSOU "citlive" v tomto smyslu: jejich hodnota se
//     nenahrazuje pausalne, ale zkracuje - viz cardNumberKeys.phpt ---
Assert::false($s->isSensitiveKey('pan'));
Assert::false($s->isSensitiveKey('cardNumber'));

// tohle je duvod, proc kratke terminy nesmi byt podretezec:
Assert::false($s->isSensitiveKey('shippingAddress'), '"shipping" obsahuje "pin"');
Assert::false($s->isSensitiveKey('shipping_address'));
Assert::false($s->isSensitiveKey('mapping'));
Assert::false($s->isSensitiveKey('spinner'));
Assert::false($s->isSensitiveKey('company'), '"company" obsahuje "pan"');
Assert::false($s->isSensitiveKey('expansion'), '"expansion" obsahuje "pan"');

// --- bezna nesouvisejici pole zustavaji ---
Assert::false($s->isSensitiveKey('email'));
Assert::false($s->isSensitiveKey('amount'));
Assert::false($s->isSensitiveKey('identifier'));
Assert::false($s->isSensitiveKey('author'), '"author" nesmi trefit "authorization"');

// --- vlastni klice a vzory ---
Assert::false($s->isSensitiveKey('rodneCislo'));
Assert::true((new SensitiveDataSanitizer())->addSensitiveKeys('rodneCislo')->isSensitiveKey('rodne_cislo'));
Assert::true((new SensitiveDataSanitizer(sensitivePatterns: ['/^x-internal-/i']))->isSensitiveKey('X-Internal-Trace'));
