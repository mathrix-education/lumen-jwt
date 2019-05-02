<?php

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Carbon\Carbon;
use Exception;
use Faker\Provider\Uuid;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\Serializer;
use Mathrix\Lumen\JWT\Auth\HasJWT;

/**
 * Class JWTIssuer.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 5.0.2
 */
class JWTIssuer extends JWTManager
{
    /**
     * Get the JWS payload.
     *
     * @param HasJWT $user
     *
     * @return string
     */
    private static function getPayload($user): string
    {
        $now = Carbon::now();

        $payload = json_encode([
            "iss" => config("jwt_auth.jwt.iss"),
            "sub" => $user->getSubject(),
            "aud" => config("jwt_auth.jwt.aud"),
            "exp" => $now->copy()->addMonth(3)->timestamp,
            "nbf" => $now->timestamp,
            "iat" => $now->timestamp,
            "jti" => Uuid::uuid(),
            "scopes" => $user->getScopes()
        ]);

        return $payload;
    }


    /**
     * @param HasJWT $user
     *
     * @return JWS
     */
    public static function issueJWS($user): JWS
    {
        $jwk = self::getJWK();
        $jwsBuilder = new JWSBuilder(null, app()->make(AlgorithmManager::class));

        $jws = $jwsBuilder->create()
            ->withPayload(self::getPayload($user))
            ->addSignature($jwk, [
                "typ" => "JWT",
                "alg" => class_basename(app()->make(Algorithm::class))
            ])
            ->build();

        return $jws;
    }


    /**
     * Serialize an existing JWS.
     *
     * @param JWS $jws
     *
     * @return string
     * @throws Exception
     */
    public static function serializeJWS(JWS $jws)
    {
        /** @var Serializer $serializer */
        $serializer = app()->make(Serializer::class);

        return $serializer->serialize($jws);
    }


    /**
     * Issue a serialized JWS
     *
     * @param HasJWT $user The user who belongs the JWS.
     *
     * @return string The serialized JWS.
     * @throws Exception
     */
    public static function issueJWSSerialized($user): string
    {
        $jws = self::issueJWS($user);

        return self::serializeJWS($jws);
    }
}
