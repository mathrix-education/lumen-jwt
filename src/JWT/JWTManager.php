<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use function config;
use function file_get_contents;

/**
 * Base class to interact with the stored JWK.
 */
abstract class JWTManager
{
    /**
     * Get the JWK path.
     *
     * @return string
     */
    public function getJWKPath(): string
    {
        return config('jwt_auth.key.path');
    }

    /**
     * Get the JWK.
     *
     * @return JWK|JWKSet
     */
    protected function getJWK(): JWK
    {
        return JWKFactory::createFromJsonObject(file_get_contents($this->getJWKPath()));
    }

    /**
     * Get the public JWK.
     *
     * @return JWK
     */
    public function getJWKPublic(): JWK
    {
        return $this->getJWK()->toPublic();
    }
}
