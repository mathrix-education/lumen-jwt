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

/**
 * Driver for RSA.
 */
class RSADriver extends Driver
{
    public const NAME       = 'rsa';
    public const ALGORITHMS = [
        RS256::class,
        RS384::class,
        RS512::class,
        PS256::class,
        PS384::class,
        PS512::class,
    ];

    /** @var int The RSA key size in bits. */
    private int $size;

    public function __construct(array $config)
    {
        $this->size = $config['size'];
        parent::__construct($config);
    }

    /**
     * @inheritDoc
     */
    protected function generate(): JWK
    {
        return JWKFactory::createRSAKey($this->size);
    }
}
