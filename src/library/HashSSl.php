<?php

namespace BingoCart\library;

use HashContext;

class HashSSl
{
    private string $privatePEM;
    private string $secret;

    public function __construct(private string $pathToP12, private string $secretCert)
    {
        if (count($p12 = glob($this->pathToP12)) > 0) {
            $certP12 = file_get_contents($p12[0]);
            openssl_pkcs12_read($certP12, $certPEM, $this->secretCert);
            $this->privatePEM = $certPEM['pkey'];
        } else {
            throw new \Exception('Private key not found');
        }
        $this->secret = base64_encode(hash('SHA512', $this->privatePEM, true));
    }

    public static function HashInit(string $algo, string $secret): HashContext
    {
        return hash_init($algo, HASH_HMAC, $secret);
    }

    public function Hash(string $algo, string $data, bool $binary = false)
    {
        if ($binary)
            return hex2bin(hash_hmac($algo, $data, $this->secret));
        else
            return hash_hmac($algo, $data, $this->secret);
    }

    public function getSecret()
    {
        return $this->secret;
    }
}
