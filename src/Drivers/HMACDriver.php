<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;

/**
 * Driver for HMAC.
 */
class HMACDriver extends Driver
{
    public const NAME       = 'hmac';
    public const ALGORITHMS = [
        HS256::class,
        HS384::class,
        HS512::class,
    ];

    /** @var int The HMAC key size in bits. */
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
        return JWKFactory::createOctKey($this->size);
    }
}
