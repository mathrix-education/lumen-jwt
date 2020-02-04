<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;

/**
 * Driver for Edwards elliptic curves.
 */
class EdDSADriver extends Driver
{
    public const NAME          = 'eddsa';
    public const CURVE_ED25519 = 'Ed25519';
    public const CURVES        = [self::CURVE_ED25519];
    public const ALGORITHMS    = [EdDSA::class];

    /** @var string The elliptic curve to use. */
    private string $curve;

    public function __construct(array $config)
    {
        $this->curve = $config['curve'] ?? self::CURVE_ED25519;
        parent::__construct($config);
    }

    /**
     * @inheritDoc
     */
    protected function generate(): JWK
    {
        return JWKFactory::createOKPKey($this->curve);
    }
}
