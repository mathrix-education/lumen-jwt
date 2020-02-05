<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use function implode;

/**
 * Driver for Edwards elliptic curves.
 */
class EdDSADriver extends Driver
{
    public const NAME          = 'EdDSA';
    public const LIBRARY       = 'web-token/jwt-signature-algorithm-eddsa';
    public const CURVE_ED25519 = 'Ed25519';
    public const CURVES        = [self::CURVE_ED25519];
    public const ALGORITHMS    = [EdDSA::class];

    /** @var string The elliptic curve to use. */
    private string $curve;

    /**
     * @inheritDoc
     */
    protected function getSupportedAlgorithms(array $keyConfig): array
    {
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
        return JWKFactory::createOKPKey($this->curve);
    }

    /**
     * @inheritDoc
     */
    protected function postApply(array $keyConfig): void
    {
        $this->curve = $keyConfig['curve'];
    }
}
