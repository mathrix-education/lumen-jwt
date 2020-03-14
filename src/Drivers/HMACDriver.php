<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use const INF;

/**
 * Driver for HMAC.
 */
class HMACDriver extends Driver
{
    public const NAME       = 'HMAC';
    public const LIBRARY    = 'web-token/jwt-signature-algorithm-hmac';
    public const ALGORITHMS = [HS256::class, HS384::class, HS512::class];

    /** @var int The HMAC key size in bits. */
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
            case HS256::class:
                return 256;
            case HS384::class:
                return 384;
            case HS512::class:
                return 512;
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

                    $fail("$attribute: RSA key size must be a multiple of 8, but got $value.");
                },
                function (string $attribute, $value, callable $fail) use ($keyConfig) {
                    $algorithm   = $keyConfig['algorithm'] ?? 'invalid';
                    $minimumSize = $this->getMinimumKeySize($algorithm);

                    if ($value >= $minimumSize) {
                        return;
                    }

                    $fail("$attribute: HMAC key size must at least $minimumSize bits while using $algorithm, but got "
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
        return JWKFactory::createOctKey($this->size);
    }

    /**
     * @inheritDoc
     */
    protected function postApply(array $keyConfig): void
    {
        $this->size = (int)$keyConfig['size'];
    }
}
