<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use const INF;

/**
 * Driver for RSA.
 */
class RSADriver extends Driver
{
    public const NAME       = 'RSA';
    public const LIBRARY    = 'web-token/jwt-signature-algorithm-rsa';
    public const ALGORITHMS = [
        RS256::class,
        RS384::class,
        RS512::class,
        PS256::class,
        PS384::class,
        PS512::class,
    ];

    /** @var int The RSA key size in bits. */
    private $size;

    /**
     * @inheritDoc
     */
    protected function getSupportedAlgorithms(array $keyConfig): array
    {
        return self::ALGORITHMS;
    }

    /**
     * Get the minimum key size based on the choose algorithm.
     *
     * @param string $algorithm
     *
     * @return int
     */
    private function getMinimumKeySize(string $algorithm): int
    {
        switch ($algorithm) {
            case PS256::class:
            case RS256::class:
                return 2048;
            case PS384::class:
            case RS384::class:
                return 3072;
            case PS512::class:
            case RS512::class:
                return 4096;
            default:
                return INF;
        }
    }

    /**
     * @inheritDoc
     */
    protected function getValidationRules(array $keyConfig): array
    {
        return [
            'size' => [
                'required',
                static function (string $attribute, $value, callable $fail) {
                    if ($value % 8 === 0) {
                        return;
                    }

                    $fail("$attribute: RSA key size must be a multiple of 8, but got $value");
                },
                function (string $attribute, $value, callable $fail) use ($keyConfig) {
                    $algorithm   = $keyConfig['algorithm'] ?? 'invalid';
                    $minimumSize = $this->getMinimumKeySize($algorithm);

                    if ($value >= $minimumSize) {
                        return;
                    }

                    $fail("$attribute: RSA key size must at least $minimumSize bits while using $algorithm, but got "
                        . "$value.");
                },
            ],
        ];
    }

    /**
     * @inheritDoc
     */
    protected function generate(): JWK
    {
        return JWKFactory::createRSAKey($this->size);
    }

    /**
     * @inheritDoc
     */
    protected function postApply(array $keyConfig): void
    {
        $this->size = (int)$keyConfig['size'];
    }
}
