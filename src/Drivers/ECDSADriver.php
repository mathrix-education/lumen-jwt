<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;

/**
 * Driver for elliptic curves.
 */
class ECDSADriver extends Driver
{
    public const NAME       = 'ecdsa';
    public const CURVE_P256 = 'P-256';
    public const CURVE_P384 = 'P-384';
    public const CURVE_P521 = 'P-521';
    public const CURVES     = [self::CURVE_P256, self::CURVE_P384, self::CURVE_P521];
    public const ALGORITHMS = [ES256::class, ES384::class, ES512::class];

    /** @var string The elliptic curve to use. */
    private string $curve;

    public function __construct(array $config)
    {
        $this->curve = $config['curve'] ?? self::CURVE_P521;
        parent::__construct($config);
    }

    /**
     * @inheritDoc
     */
    protected function generate(): JWK
    {
        return JWKFactory::createECKey($this->curve);
    }
}
