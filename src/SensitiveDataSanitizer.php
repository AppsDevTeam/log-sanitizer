<?php

declare(strict_types=1);

namespace ADT\LogSanitizer;

/**
 * Odstrani citliva data z payloadu, nez se ulozi do logu.
 *
 * Urceno pro request/response logy, auditni zaznamy a cokoliv dalsiho, kde
 * se uklada obsah, ktery slozil nekdo jiny - tedy tam, kde nejde predem
 * rict, co v nem bude.
 *
 * Zamerne BEZ zavislosti (jen ext-mbstring): pouzitelne z knihovny,
 * z presenteru i z konzole, bez ohledu na framework.
 *
 * Sluzba je request-scoped: `hideValue()` registruje tajemstvi platne pro
 * probihajici pozadavek. V klasickem PHP-FPM zivotnim cyklu je to v poradku;
 * ve dlouhozijicim workeru by se seznam prenasel mezi pozadavky, coz vede
 * nejvys k prilisnemu maskovani, nikdy k uniku.
 */
final class SensitiveDataSanitizer
{
	public const string MASK = '***';

	/**
	 * Vychozi citlive klice.
	 *
	 * Kratke termity (pod 5 znaku) se poroKvnavaji na CELE SLOVO, delsi jako
	 * podretezec - viz isSensitiveKey(). Diky tomu 'password' pokryje
	 * i 'passwordConfirm', ale 'pin' nezamaskuje 'shippingAddress'.
	 */
	public const array DEFAULT_SENSITIVE_KEYS = [
		// autentizace
		'password', 'passwd', 'pwd', 'secret', 'token', 'authorization',
		'api_key', 'private_key', 'refresh_token', 'access_token',
		// SAD - nesmi se ukladat vubec, takze cela hodnota pryc
		'cvv', 'cvc', 'cid', 'pin', 'pin_block', 'track',
		// session
		'cookie', 'session_id',
	];

	/**
	 * Klice nesouci cislo karty. Jejich hodnota se NEnahrazuje pausalne, ale
	 * projde maskovanim cisel karet - takze:
	 *
	 *   'PAN' => '4111111111111111'  ->  '************1111'
	 *   'MaskedPAN' => '************3035'  ->  bez zmeny
	 *
	 * Uz zkracene cislo z terminalu je bezpecne (PCI DSS pripousti zkraceni
	 * jako metodu) a soucasne potrebne k parovani a reklamacim, takze ho
	 * pausalni '***' jen zbytecne znicí.
	 */
	public const array CARD_NUMBER_KEYS = ['pan', 'card_number'];

	/**
	 * Prefixy a delky hlavnich karetnich schemat (ISO/IEC 7812).
	 *
	 * POUZIVA SE JEN K ROZPOZNANI SCHEMATU, NE K MASKOVANI. Maskuje se
	 * schvalne siroce (delka + Luhn), protoze seznam prefixu stara: dvojkova
	 * rada MasterCard (2221-2720) prisla az v roce 2017 a regexy, ktere ji
	 * nemely, tise propoustely platne karty. U sanitizeru je falesne negativni
	 * shoda drazsi nez falesne pozitivni.
	 *
	 * Prefix se hodi na neco jineho: shoda znamena "tohle je hodne
	 * pravdepodobne skutecny PAN", coz je signal, ze je rozbita integrace
	 * vys - viz onCardNumberDetected().
	 */
	public const array CARD_SCHEMES = [
		'Visa' => '/^4\d{12}(\d{3})?(\d{3})?$/',
		'MasterCard' => '/^(5[1-5]\d{14}|2(22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})$/',
		'Amex' => '/^3[47]\d{13}$/',
		'Discover' => '/^(6011\d{12}|65\d{14}|64[4-9]\d{13})$/',
		'DinersClub' => '/^(30[0-5]\d{11}|3[68]\d{12})$/',
		'JCB' => '/^35(2[89]|[3-8]\d)\d{12}$/',
		'UnionPay' => '/^62\d{14,17}$/',
		'Maestro' => '/^(5018|5020|5038|5893|6304|6759|676[1-3])\d{8,15}$/',
	];

	/**
	 * Hlavicky, ktere se do logu nedostanou VUBEC (ani zamaskovane) - jejich
	 * pritomnost sama o sobe nema diagnostickou hodnotu.
	 */
	public const array DEFAULT_DROPPED_HEADERS = [
		'authorization', 'proxy-authorization', 'x-api-key', 'cookie', 'set-cookie',
	];

	/** delka, od ktere se termin porovnava jako podretezec misto celeho slova */
	private const int SUBSTRING_THRESHOLD = 5;

	/** kanonicky tvar UUID (8-4-4-4-12 hexadecimalnich znaku) */
	private const string UUID_PATTERN = '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i';

	/** samostatne cislo delky PANu, pripoustejici oddelovace mezi skupinami */
	private const string CARD_CANDIDATE_PATTERN = '/(?<![\d])\d[\d \-]{11,21}\d(?![\d])/';

	/** base64 delsi nez tohle se nahradi hashem - typicky obrazky a prilohy */
	private const int BASE64_HASH_THRESHOLD = 255;

	/** @var list<string> tajemstvi registrovana za behu pozadavku */
	private array $hiddenValues = [];

	/** @var (callable(string, int): void)|null */
	private $cardNumberListener = null;

	/**
	 * @param list<string> $sensitiveKeys nazvy klicu, jejichz hodnota se maskuje
	 * @param list<string> $sensitivePatterns regularni vyrazy pro nazvy klicu
	 *        (escape hatch, kdyz porovnani podle slov nestaci)
	 * @param list<string> $droppedHeaders hlavicky vynechane z logu uplne
	 * @param bool $maskCardNumbers hledat v hodnotach cisla karet (regex + Luhn)
	 */
	public function __construct(
		private array $sensitiveKeys = self::DEFAULT_SENSITIVE_KEYS,
		private array $sensitivePatterns = [],
		private array $droppedHeaders = self::DEFAULT_DROPPED_HEADERS,
		private bool $maskCardNumbers = true,
	) {
	}

	/** Prida dalsi citlive klice k vychozim. */
	public function addSensitiveKeys(string ...$keys): static
	{
		foreach ($keys as $key) {
			$this->sensitiveKeys[] = $key;
		}

		return $this;
	}

	/**
	 * Zaregistruje konkretni tajemstvi, ktere se zamaskuje, KDEKOLIV se objevi
	 * - i v hodnote nesouvisejiciho klice nebo uprostred textu.
	 *
	 * Pro hodnoty, ktere vznikaji za behu a nemaji stabilni nazev klice:
	 *
	 *   $token = $this->tokenService->create(...);
	 *   $sanitizer->hideValue($token);
	 *   $this->sendJsonResponse(['token' => $token]);
	 */
	public function hideValue(?string $secret): static
	{
		// kratke hodnoty by zamaskovaly pul logu
		if ($secret !== null && mb_strlen($secret) >= 8) {
			$this->hiddenValues[] = $secret;
		}

		return $this;
	}

	/**
	 * Zavola se, kdyz zamaskovane cislo odpovida prefixu nekterého karetniho
	 * schematu - tedy kdyz je hodne pravdepodobne, ze slo o skutecny PAN.
	 *
	 * Existuje proto, aby se nemaskovalo POTICHU: PAN v logu znamena rozbitou
	 * integraci vys a nekdo se to musi dozvedet, jinak zustane databaze cista
	 * a pokladna posila PAN dal i jinam.
	 *
	 * Listener dostane NAZEV SCHEMATU A DELKU, nikdy hodnotu - jinak by
	 * varovani bylo dalsim mistem, kde PAN unikne.
	 *
	 * @param callable(string, int): void $listener
	 */
	public function onCardNumberDetected(callable $listener): static
	{
		$this->cardNumberListener = $listener;

		return $this;
	}

	/** Rozpozna karetni schema podle prefixu a delky; null = zadne neznamé. */
	public static function detectCardScheme(string $digits): ?string
	{
		foreach (self::CARD_SCHEMES as $scheme => $pattern) {
			if (preg_match($pattern, $digits) === 1) {
				return $scheme;
			}
		}

		return null;
	}

	/**
	 * Kopie bez maskovani cisel karet.
	 *
	 * Withrem, ne setterem: sanitizer se registruje jako sdilena sluzba, takze
	 * vypnuti na miste by ho vyplo i vsem ostatnim volajicim.
	 *
	 * Ma to smysl u dat, kde karetni cisla z podstaty nejsou a maskovani by
	 * naopak nici uzitecny obsah - napr. podpisove kody v EET XML jsou
	 * skupiny cislic oddelene pomlckami a Luhnem projde kazda desata.
	 */
	public function withoutCardNumberMasking(): self
	{
		$clone = clone $this;
		$clone->maskCardNumbers = false;

		return $clone;
	}

	/**
	 * Ocisti libovolnou strukturu - skalar, pole i vnorene pole.
	 *
	 * Klice zustavaji, meni se jen hodnoty: v logu ma zustat videt, ZE pole
	 * prislo, jen ne s cim.
	 */
	public function sanitize(mixed $data): mixed
	{
		if (is_array($data)) {
			$output = [];
			foreach ($data as $key => $value) {
				// i KLIC musi byt ulozitelny: nevalidni UTF-8 v nazvu pole
				// (utocny request posila i takove) rozbije json_encode uplne
				// stejne jako v hodnote a log by se neulozil vubec
				$cleanKey = is_string($key) ? self::sanitizeKey($key) : $key;

				// prazdna hodnota se nemaskuje: skryt neni co a v logu je rozdil
				// mezi "pole bylo prazdne" a "pole melo hodnotu" diagnosticky
				if (!is_string($cleanKey) || self::isEmptyValue($value)) {
					$output[$cleanKey] = $this->sanitize($value);
					continue;
				}

				if (self::matchesKey($cleanKey, self::CARD_NUMBER_KEYS)) {
					$output[$cleanKey] = $this->sanitizeCardNumberValue($value);
					continue;
				}

				$output[$cleanKey] = $this->isSensitiveKey($cleanKey)
					? self::MASK
					: $this->sanitize($value);
			}

			return $output;
		}

		if ($data instanceof \stdClass) {
			return $this->sanitize((array) $data);
		}

		if (is_string($data)) {
			return $this->sanitizeString($data);
		}

		return $data;
	}

	/**
	 * Ocisti JSON a vrati zpatky JSON. Kdyz vstup neni platny JSON, ocisti se
	 * jako holy text - takze surove telo requestu jde poslat sem tak, jak je.
	 */
	public function sanitizeJson(?string $json): ?string
	{
		if ($json === null || $json === '') {
			return $json;
		}

		if (!json_validate($json)) {
			return $this->sanitizeString($json);
		}

		$sanitized = $this->sanitize(json_decode($json, associative: true));

		return json_encode($sanitized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
	}

	/**
	 * Ocisti HTTP hlavicky: nositele pristupu vyhodi uplne, ostatni ocisti
	 * jako hodnoty.
	 *
	 * @param array<string, mixed> $headers
	 * @return array<string, mixed>
	 */
	public function sanitizeHeaders(array $headers): array
	{
		$output = [];
		foreach ($headers as $name => $value) {
			if (in_array(mb_strtolower((string) $name), $this->droppedHeaders, true)) {
				continue;
			}

			$output[$name] = $this->isSensitiveKey((string) $name)
				? self::MASK
				: $this->sanitize($value);
		}

		return $output;
	}

	/**
	 * Je nazev klice citlivy?
	 *
	 * Nazev se rozpadne na slova (camelCase i snake_case), pak:
	 *  - termin od SUBSTRING_THRESHOLD znaku se hleda jako podretezec
	 *    ('password' zabere i na 'passwordConfirm', 'token' na 'accessToken')
	 *  - kratsi termin musi trefit CELE SLOVO ('pin' zabere na 'card_pin',
	 *    ale ne na 'shippingAddress' - to je past ciste podretezcove shody)
	 */
	public function isSensitiveKey(string $key): bool
	{
		return self::matchesKey($key, $this->sensitiveKeys) || $this->matchesPattern($key);
	}

	/**
	 * Hodnota pod klicem, ktery nese cislo karty: zkrati se na poslednich ctyr
	 * cislic. Kdyz je maskovani karet vypnute, nesmi projit vubec.
	 */
	private function sanitizeCardNumberValue(mixed $value): mixed
	{
		if (!$this->maskCardNumbers) {
			return self::MASK;
		}

		$sanitized = $this->sanitize($value);

		// zachytna sit: cislo, ktere neproslo Luhnem (preklep v testovacich
		// datech, jiny format), pod vyslovne karetnim klicem projit nesmi
		if (is_string($sanitized) && preg_match('/\d{13,19}/', $sanitized) === 1) {
			return self::MASK;
		}

		return $sanitized;
	}

	/** @param list<string> $terms */
	private static function matchesKey(string $key, array $terms): bool
	{
		$words = self::words($key);
		$joined = implode('', $words);

		foreach ($terms as $sensitiveKey) {
			$termWords = self::words($sensitiveKey);
			$term = implode('', $termWords);

			if ($term === '') {
				continue;
			}

			if (mb_strlen($term) >= self::SUBSTRING_THRESHOLD) {
				if (str_contains($joined, $term)) {
					return true;
				}
			} elseif (in_array($term, $words, true)) {
				return true;
			}
		}

		return false;
	}

	private function matchesPattern(string $key): bool
	{
		foreach ($this->sensitivePatterns as $pattern) {
			if (preg_match($pattern, $key) === 1) {
				return true;
			}
		}

		return false;
	}

	private function sanitizeString(string $value): string
	{
		foreach ($this->hiddenValues as $secret) {
			$value = str_replace($secret, self::MASK, $value);
		}

		// neplatne UTF-8 (typicky z utocnych requestu) by rozbilo json_encode
		// pri zapisu logu, takze se prevede jeste pred ulozenim
		if (!mb_check_encoding($value, 'UTF-8')) {
			$value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
		}

		$value = self::removeControlCharacters($value);

		if (strlen($value) >= self::BASE64_HASH_THRESHOLD && self::isBase64($value)) {
			return 'md5:' . md5($value);
		}

		if ($this->maskCardNumbers) {
			$value = $this->maskCardNumbersIn($value);
		}

		return $value;
	}

	/**
	 * Nahradi cisla karet za '******' + poslednich ctyr cislic. Kandidat musi
	 * projit Luhnovou kontrolou, aby se nemaskovala kazda delsi cislice
	 * (objednavky, EAN, IC).
	 */
	private function maskCardNumbersIn(string $value): string
	{
		/** @var list<array{int, int}>|null $uuidRanges pocita se az pri prvnim kandidatovi */
		$uuidRanges = null;
		$output = '';
		$cursor = 0;

		while (preg_match(self::CARD_CANDIDATE_PATTERN, $value, $matches, PREG_OFFSET_CAPTURE, $cursor) === 1) {
			[$candidate, $offset] = $matches[0];
			$masked = $this->maskCardNumberCandidate($candidate, $offset, $value, $uuidRanges);

			if ($masked !== null) {
				$output .= substr($value, $cursor, $offset - $cursor) . $masked;
				$cursor = $offset + strlen($candidate);
				continue;
			}

			// Zamitnuty kandidat se NEpreskakuje cely, posouvame se o znak.
			// Kandidat je hladovy a oddelovace bere jako soucast cisla, takze
			// zacne v necem jinem a skonci uprostred skutecneho PANu za nim
			// ("...ad8d71 4111111111111111" -> "71 4111111111111111",
			// 18 cislic, Luhn neprojde). Preskocenim cele shody by PAN zustal
			// v logu nezamaskovany. Dalsi hledani zacne az za prvni cislici -
			// diky (?<!\d) se stejne chyti az dalsi samostatne cislo.
			$output .= substr($value, $cursor, $offset - $cursor + 1);
			$cursor = $offset + 1;
		}

		return $output . substr($value, $cursor);
	}

	/**
	 * Zamaskovana podoba kandidata, nebo null, kdyz o cislo karty nejde.
	 *
	 * @param list<array{int, int}>|null $uuidRanges cache pozic UUID v $subject
	 */
	private function maskCardNumberCandidate(string $candidate, int $offset, string $subject, ?array &$uuidRanges): ?string
	{
		$digits = preg_replace('/\D/', '', $candidate) ?? '';
		$length = strlen($digits);

		if ($length < 13 || $length > 19 || !self::isLuhnValid($digits)) {
			return null;
		}

		// Luhnem projde nahodou kazde desate cislo, takze samotny Luhn
		// nestaci: casova znacka typu 20250909095540 ma 14 cislic a v
		// desetine pripadu by se zamaskovala. Zadne schema karet
		// nezacina 19xx ani 20xx, takze vylouceni casovych znacek
		// realne karty neminie.
		if (self::looksLikeTimestamp($digits)) {
			return null;
		}

		// UUID je hex s pomlckami, takze jeho cislice splynou v kandidata
		// stejne jako oddelovaci zapis PANu - a kazdy desaty projde Luhnem.
		// Napr. d5018957-3288-49bb-... da 5018957328849: 13 cislic, platny
		// Luhn, prefix 5018 = Maestro. Identifikator tak skonci zamaskovany
		// a zaznam nedohledatelny, jeste k tomu s planym poplachem
		// o nemaskovanem PANu. Skutecny PAN uvnitr UUID nikdy nelezi.
		$uuidRanges ??= self::uuidRanges($subject);
		foreach ($uuidRanges as [$start, $end]) {
			// jen kandidat CELY uvnitr UUID; ten, ktery z nej vybiha,
			// uz muze nest cislo zapsane za identifikatorem
			if ($offset >= $start && $offset + strlen($candidate) <= $end) {
				return null;
			}
		}

		// prefix schematu = vysoka jistota, ze to je skutecny PAN;
		// tehdy ma smysl upozornit, ze je rozbita integrace vys
		if ($this->cardNumberListener !== null && ($scheme = self::detectCardScheme($digits)) !== null) {
			($this->cardNumberListener)($scheme, $length);
		}

		return str_repeat('*', $length - 4) . substr($digits, -4);
	}

	/**
	 * Pozice vsech UUID v retezci jako dvojice [zacatek, konec].
	 *
	 * @return list<array{int, int}>
	 */
	private static function uuidRanges(string $subject): array
	{
		if (!preg_match_all(self::UUID_PATTERN, $subject, $matches, PREG_OFFSET_CAPTURE)) {
			return [];
		}

		$ranges = [];
		foreach ($matches[0] as [$uuid, $offset]) {
			$ranges[] = [$offset, $offset + strlen($uuid)];
		}

		return $ranges;
	}

	/** YYYYMMDDHHMMSS(mmm) nebo unixovy cas v milisekundach */
	private static function looksLikeTimestamp(string $digits): bool
	{
		$length = strlen($digits);

		if ($length === 13) {
			// milisekundy od epochy pro roky ~2001-2033
			return $digits >= '1000000000000' && $digits <= '2000000000000';
		}

		if ($length === 14 || $length === 17) {
			[$year, $month, $day, $hour, $minute, $second] = [
				(int) substr($digits, 0, 4), (int) substr($digits, 4, 2), (int) substr($digits, 6, 2),
				(int) substr($digits, 8, 2), (int) substr($digits, 10, 2), (int) substr($digits, 12, 2),
			];

			return $year >= 1970 && $year <= 2099
				&& $month >= 1 && $month <= 12
				&& $day >= 1 && $day <= 31
				&& $hour <= 23 && $minute <= 59 && $second <= 59;
		}

		return false;
	}

	/**
	 * Nazev klice jen ocisti, aby byl ulozitelny - zadne maskovani ani
	 * hledani karet: to jsou operace nad obsahem, ne nad strukturou.
	 */
	private static function sanitizeKey(string $key): string
	{
		if (!mb_check_encoding($key, 'UTF-8')) {
			$key = mb_convert_encoding($key, 'UTF-8', 'UTF-8');
		}

		return self::removeControlCharacters($key);
	}

	private static function isEmptyValue(mixed $value): bool
	{
		return $value === null || $value === '' || $value === [];
	}

	private static function isLuhnValid(string $digits): bool
	{
		$sum = 0;
		$double = false;

		for ($i = strlen($digits) - 1; $i >= 0; $i--) {
			$digit = (int) $digits[$i];

			if ($double) {
				$digit *= 2;
				if ($digit > 9) {
					$digit -= 9;
				}
			}

			$sum += $digit;
			$double = !$double;
		}

		return $sum % 10 === 0;
	}

	/** @return list<string> */
	private static function words(string $key): array
	{
		$spaced = preg_replace('/(?<=[\p{Ll}\p{N}])(?=\p{Lu})/u', ' ', $key) ?? $key;
		$words = preg_split('/[^\p{L}\p{N}]+/u', mb_strtolower($spaced), -1, PREG_SPLIT_NO_EMPTY);

		return $words === false ? [] : $words;
	}

	private static function removeControlCharacters(string $input): string
	{
		return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $input) ?? $input;
	}

	private static function isBase64(string $string): bool
	{
		$decoded = base64_decode($string, true);

		return $decoded !== false && base64_encode($decoded) === $string;
	}
}
