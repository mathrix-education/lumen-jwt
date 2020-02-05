<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use function array_search;
use function implode;

/**
 * Driver for elliptic curves.
 */
class ECDSADriver extends Driver
{
    public const NAME       = 'ECDSA';
    public const LIBRARY    = 'web-token/jwt-signature-algorithm-ecdsa';
    public const ALGORITHMS = [ES256::class, ES384::class, ES512::class];
    public const CURVE_P256 = 'P-256';
    public const CURVE_P384 = 'P-384';
    public const CURVE_P521 = 'P-521';
    public const CURVES     = [self::CURVE_P256, self::CURVE_P384, self::CURVE_P521];

    /** @var string The elliptic curve to use. */
    private string $curve;

    /**
     * @inheritDoc
     */
    protected function getSupportedAlgorithms(array $keyConfig): array
    {
        if (isset($keyConfig['curve'])) {
            $curveIndex = array_search($keyConfig['curve'], self::CURVES, true);

            if ($curveIndex !== false) {
                return [self::ALGORITHMS[$curveIndex]];
            }
        }

        return self::ALGORITHMS;
    }

    /**
     * @inheritDoc
     */
    protected function getValidationRules(array $keyConfig): array
    {
        return [
            'curve' => 'required|in:' . implode(',', self::CURVES),
        ];
    }

    /**
     * @inheritDoc
     */
    protected function generate(): JWK
    {
        return JWKFactory::createECKey($this->curve);
    }

    /**
     * @inheritDoc
     */
    protected function postApply(array $keyConfig): void
    {
        $this->curve = $keyConfig['curve'];
    }
}
