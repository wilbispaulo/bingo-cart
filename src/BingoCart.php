<?php

namespace BingoCart;

use BingoCart\library\HashSSl;

class BingoCart
{
    private $wordSeries = [];

    public function __construct(
        private HashSSl $hashSSL,
        private $date,
        private $serie,
        private $owner,
        private $titleSerie,
        private $titleEvent,
        private $txtJackpot
    ) {
        $this->makeHead();
        $this->wordSeries['carts'] = [];
    }

    // 
    // Generate a bingo cart series with defined quantity carts
    // A private array $wordSeries contains in each line a lenght 81 string which positions:
    // 1-3 => SERIAL CART NUMBER SULFIX
    // 4-53 => STRING CART
    // 54-81 => HMAC HASH WITH SHA1 ALGO
    //
    public function makeSeries(int $quantCart): array
    {
        $cont = 0;
        while ($cont < $quantCart) {
            $cart = $this->makeCart();
            if (($uniqueCart = $this->uniqueCart($cart)) === false) continue;
            $uniqueCart = sprintf("%03d", count($this->wordSeries['carts']) + 1) . $uniqueCart;
            $uniqueCart .= $this->hashCart($uniqueCart);
            array_push($this->wordSeries['carts'], $uniqueCart);
            $cont++;
        }
        $this->updateQuantCart();

        return $this->wordSeries;
    }


    // Test a 25 element array if contents is numeric
    public static function isNumCart(array $cart): bool
    {
        foreach ($cart as $ball) {
            $isNum = is_int($ball);
        }
        return $isNum;
    }

    // Get a hmac SHA1 hash string from a lenght 81 string cart
    public static function getHashCart(string $hashNumWordCard): string
    {
        return substr($hashNumWordCard, -28);
    }

    // Generate a sorted string from 25 numeric | string (lenght 2) elements array ($cart)
    public static function wordSortCart(array $cart): string
    {
        if (self::isNumCart($cart) === false) {
            $cart = self::strToIntCart($cart);
        }
        sort($cart, SORT_NUMERIC);
        return self::toWordCart($cart);
    }

    // Split a lenght 50 string, extracted from lenght 97 string ($hashNumWord), in to a 25 numeric elements array
    public static function splitWord(string $hashNumWord): array
    {
        $wordCart = substr($hashNumWord, 3, 50);
        $cart = str_split($wordCart, 2);
        $cart = self::strToIntCart($cart);
        return $cart;
    }

    // Convert a 25 string elements array in to a int elements array
    public static function strToIntCart(array $cart): array
    {
        $cart = array_map(function ($conv) {
            return intval($conv);
        }, $cart);
        return $cart;
    }

    // Convert 25 numeric elements array in a string (lenght 50)
    public static function toWordCart(array $cart): string
    {
        $wordCart = "";
        foreach ($cart as $ball) {
            $wordCart .= sprintf("%02d", $ball);
        }
        return $wordCart;
    }

    public static function signJson(string $json, string $privateKey)
    {
        $sign = '';
        openssl_sign($json, $sign, $privateKey, OPENSSL_ALGO_SHA512);
        $array = json_decode($json, true);
        $array['sign_sha512'] = base64_encode($sign);
        return json_encode($array, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public static function validateSignJson(string $json, string $pathToCert): bool
    {
        $publicKey = openssl_pkey_get_details(openssl_pkey_get_public(file_get_contents($pathToCert)['key']));
        $serie = json_decode($json, true);

        // VALIDATE KEY
        if (!array_key_exists('sign_sha512', $serie)) {
            return 0;
        }

        // VALIDATE SIGN
        $sign['sign_sha512'] = $serie['sign_sha512'];

        $data = json_encode(array_diff_assoc($serie, $sign), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $signOk = openssl_verify($data, base64_decode($sign['sign_sha512']), $publicKey, OPENSSL_ALGO_SHA512);

        return ($signOk === 1);
    }

    // Update hmac hash with SHA512 algo using KEY_HMAC key
    private function updateHashSeries()
    {
        $this->wordSeries['head']['hash'] = $this->generateHashSeries($this->wordSeries);
    }


    // Check a cart series if is valid using hmac hash sha512 algo
    public function checkSeries(array $series): bool
    {
        $hash = $this->generateHashSeries($series);
        if ($hash === $series['head']['hash']) return true;
        return false;
    }

    // Check a lenght 81 string is valid cart using hmac hash SHA1 algo
    public function checkCart(string $hashNumWordCart): bool
    {
        $wordCart = substr($hashNumWordCart, 0, 53);
        $hashCart = self::getHashCart($hashNumWordCart);
        if (false === ($this->hashCart($wordCart) === $hashCart)) return false;
        return true;
    }

    // Generate hmac hash with SHA1 algo using KEY_HMAC key
    public function hashCart(string $word): string
    {
        return base64_encode($this->hashSSL->Hash('sha1', $word, true));
    }

    // Generate hmac hash with SHA512 algo using KEY_HMAC key
    public function generateHashSeries(array $series): string
    {
        $hash = $this->hashSSL->HashInit('sha512', $this->hashSSL->getSecret());
        foreach ($series['head'] as $index => $line) {
            if ($index !== 'hash') hash_update($hash, $line);
        }
        if (isset($series['carts'])) {
            foreach ($series['carts'] as $line) {
                hash_update($hash, $line);
            }
        }

        return base64_encode(hex2bin(hash_final($hash)));
    }

    public function getPrefixSerial(): string
    {
        return $this->wordSeries['head']['prefix_serial'];
    }

    public function getDate(): string
    {
        return $this->wordSeries['head']['date'];
    }

    public function getTitleSerie(): string
    {
        return $this->wordSeries['head']['title_serie'];
    }

    public function getTitleEvent(): string
    {
        return $this->wordSeries['head']['title_event'];
    }

    public function getTxtJackpot(): string
    {
        return $this->wordSeries['head']['jackpot'];
    }

    public function getQuantCart(): int
    {
        return $this->wordSeries['head']['qty_cart'];
    }

    public function getWordSeries(): array
    {
        return $this->wordSeries;
    }

    // Set a private prefix serial ($prefixSerial) with date and serie

    public function setDate(string $date)
    {
        $this->date = $date;
        $this->makeHead();
    }

    public function setSerie(string $serie)
    {
        $this->serie = $serie;
        $this->makeHead();
    }

    public function setTitleSerie(string $title)
    {
        $this->titleSerie = $title;
        $this->makeHead();
    }

    public function setTitleEvent(string $title)
    {
        $this->titleEvent = $title;
        $this->makeHead();
    }

    public function setTxtJackpot(string $jackpot)
    {
        $this->txtJackpot = $jackpot;
        $this->makeHead();
    }

    // Generate a header of private bingo series carts array ($wordSeries['head'])
    private function makeHead()
    {
        $this->wordSeries['head'] = [];
        $this->setPrefixSerial();
        $this->wordSeries['head']['date'] = $this->date;
        $this->wordSeries['head']['title_serie'] = $this->titleSerie;
        $this->wordSeries['head']['title_event'] = $this->titleEvent;
        $this->wordSeries['head']['jackpot'] = $this->txtJackpot;
        $this->wordSeries['head']['owner'] = $this->owner;
        $this->updateQuantCart();
    }

    // Upadate the quantity carts in a header of bingo carts series array
    private function updateQuantCart()
    {
        $this->wordSeries['head']['qty_cart'] = (isset($this->wordSeries['carts'])) ? count($this->wordSeries['carts']) : 0;
    }

    // Check if a 25 numeric | string (lenght 2) elements array is unique in a lenght 81 string array line from private array ($wordSeries)
    private function uniqueCart(array $cart): string|bool
    {
        if ($this->searchCart($cart) === false)
            return self::toWordCart($cart);
        return false;
    }

    // Execute a search of 25 numeric | string (lenght 2) elements array cart in a private array what content series
    private function searchCart(array $cart): bool
    {
        $wordSortCart = self::wordSortCart($cart);
        foreach ($this->wordSeries['carts'] as $hashNumWordCart) {
            $cartInSeries = self::splitWord($hashNumWordCart);
            $wordSortCartH = self::wordSortCart($cartInSeries);
            if ($wordSortCartH === $wordSortCart) return true;
        }
        return false;
    }

    // Generate a unsorted nonrepeated random 25 numeric elements array
    private function makeCart(): array
    {
        $cart = [];
        $cont = 0;
        while ($cont < 25) {
            $ball = rand($cont % 5 * 15 + 1, ($cont % 5 + 1) * 15);
            if (array_search($ball, $cart) === false) {
                $cart[$cont] = $ball;
                $cont++;
            }
        }
        $cart[12] = 0;
        return $cart;
    }

    private function setPrefixSerial()
    {
        $prefixSerial = substr($this->date, 8, 2);
        $prefixSerial .= substr($this->date, 3, 2);
        $prefixSerial .= substr($this->date, 0, 2);
        $prefixSerial .= substr($this->serie, 0, 2);

        $this->wordSeries['head']['prefix_serial'] = $prefixSerial;
    }
}
