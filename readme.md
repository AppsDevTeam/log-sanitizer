# ADT Log Sanitizer

Odstraní citlivá data z payloadu, než se uloží do logu.

```
composer require adt/log-sanitizer
```

## Proč

Request/response logy, auditní záznamy a transakční logy ukládají obsah,
který složil někdo jiný — takže dopředu nevíš, co v něm bude. Do logu se tak
běžně dostane token, heslo z formuláře nebo číslo karty a leží tam po celou
dobu retence, čitelné pro každého, kdo má na tabulku přístup.

Balíček je bez závislostí (jen `ext-mbstring`), aby ho mohla použít knihovna,
presenter i konzolový příkaz bez ohledu na framework.

## Použití

```php
$sanitizer = new SensitiveDataSanitizer();

// pole i vnořená struktura
$sanitizer->sanitize(['email' => 'a@b.cz', 'password' => 'Tajne123']);
// => ['email' => 'a@b.cz', 'password' => '***']

// surové tělo requestu: JSON dovnitř, JSON zpátky
$sanitizer->sanitizeJson($httpRequest->getRawBody());

// hlavičky: nositele přístupu vyhodí úplně
$sanitizer->sanitizeHeaders($headers);
```

Klíče zůstávají, mění se jen hodnoty — v logu má být vidět, **že** pole
přišlo, jen ne s čím.

## Maskování podle názvu klíče

Název se rozpadne na slova (`camelCase` i `snake_case`) a pak:

- termín od 5 znaků se hledá jako **podřetězec** — `password` zabere i na
  `passwordConfirm`, `token` na `accessToken`
- kratší termín musí trefit **celé slovo** — `pin` zabere na `card_pin`,
  ale **ne** na `shippingAddress`

To druhé je důvod, proč tu není čistě podřetězcová shoda: `str_contains('shipping', 'pin')`
je `true`, takže naivní implementace zamaskuje doručovací adresu a v logu
zůstane díra, o které nikdo neví. Totéž `company` vs. `pan`.

Vlastní klíče:

```php
$sanitizer->addSensitiveKeys('rodneCislo', 'iban');

// escape hatch, když porovnání podle slov nestačí
new SensitiveDataSanitizer(sensitivePatterns: ['/^x-internal-/i']);
```

## Hodnoty bez stabilního názvu klíče

Když hodnota vzniká za běhu a může se objevit kdekoli — typicky vydaný token —
zaregistruj ji a zmizí i z nesouvisejících polí a z textu:

```php
$token = $this->tokenService->create(...);
$sanitizer->hideValue($token);
$this->sendJsonResponse(['token' => $token]);
```

Hodnoty krátší než 8 znaků se ignorují, jinak by zamaskovaly půl logu.

## Čísla karet

Zapnuté ve výchozím stavu. Hledá v hodnotách 13–19 ciferná čísla (i s mezerami
a pomlčkami), ověří **Luhnovou kontrolou** a nechá poslední čtyři číslice:

```php
$sanitizer->sanitize('platba kartou 4111 1111 1111 1111');
// => 'platba kartou ************1111'
```

Luhn je tam proto, aby se nemaskovalo každé delší číslo — objednávky, EAN
ani IČ neprojdou.

**Samotný Luhn ale nestačí:** projde jím náhodou každé desáté číslo. Časová
značka `20250909095540` má 14 cifer, spadá do rozsahu PAN, a bez další
kontroly by se v 10 % případů zamaskovala — měřeno na 20 000 reálných
značkách. Sanitizer proto vylučuje řetězce, které vypadají jako `YYYYMMDDHHMMSS`
nebo jako unixový čas v milisekundách. Žádné karetní schéma nezačíná `19xx`
ani `20xx`, takže tím o skutečné karty nepřijdeš.

Už maskovaný PAN z terminálu (`************1111`) zůstává, jak přišel.

U dat, kde by maskování vadilo, se dá vypnout: `disableCardNumberMasking()`.

## Prázdné hodnoty

Prázdná hodnota (`null`, `''`, `[]`) se nemaskuje ani pod citlivým klíčem —
skrýt není co a v logu je rozdíl mezi „pole bylo prázdné" a „pole mělo
hodnotu" diagnosticky užitečný.

## Co ještě dělá s řetězci

- **neplatné UTF-8** převede — jinak útočný request rozbije `json_encode()`
  při zápisu logu a log se neuloží vůbec
- **řídicí znaky** odstraní; `\n` a `\t` nechá
- **base64 nad 255 znaků** nahradí `md5:<hash>` — obrázky a přílohy log
  jen nafukují, hash stačí k rozpoznání, že šlo o tentýž obsah

## Testy

```
make test
```
