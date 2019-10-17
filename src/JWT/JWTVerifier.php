<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\Serializer;
use function app;

/**
 * Allow application to verify JWT.
 */
class JWTVerifier extends JWTManager
{
    /**
     * Verify a serialized JWT.
     *
     * @param string $token The serialized token string.
     *
     * @return bool
     */
    public function verify(string $token): bool
    {
        $jwk         = $this->getJWK();
        $jwsVerifier = new JWSVerifier(app()->make(AlgorithmManager::class));

        /** @var Serializer $serializer */
        $serializer = app()->make(Serializer::class);
        $jws        = $serializer->unserialize($token);

        return $jwsVerifier->verifyWithKey($jws, $jwk, 0);
    }
}
