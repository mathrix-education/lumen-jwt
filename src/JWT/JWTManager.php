<?php

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Class JWTManager.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
abstract class JWTManager
{
    /**
     * Get the public JWK.
     *
     * @return JWK
     */
    public static function getJWKPublic()
    {
        return self::getJWK()->toPublic();
    }


    /**
     * Get the JWK.
     *
     * @return JWK|JWKSet
     */
    protected static function getJWK()
    {
        return JWKFactory::createFromJsonObject(
            file_get_contents(config("jwt_auth.key.path"))
        );
    }
}
