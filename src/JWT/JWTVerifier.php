<?php

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Exception;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\Serializer;

/**
 * Class JWTVerifier.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
class JWTVerifier extends JWTManager
{
    /**
     * @param string $token The serialized token string.
     *
     * @return bool
     * @throws Exception
     */
    public static function verify(string $token)
    {
        $jwk = self::getJWK();
        $jwsVerifier = new JWSVerifier(app()->make(AlgorithmManager::class));

        /** @var Serializer $serializer */
        $serializer = app()->make(Serializer::class);
        $jws = $serializer->unserialize($token);

        return $jwsVerifier->verifyWithKey($jws, $jwk, 0);
    }
}
