<?php

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Carbon\Carbon;
use Exception;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\Serializer;
use Mathrix\Lumen\JWT\Auth\HasJWT;
use Ramsey\Uuid\Uuid;

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
     * Issue a serialized JWS
     *
     * @param HasJWT $user The user who belongs the JWS.
     * @param array $custom
     *
     * @return string The serialized JWS.
     * @throws Exception
     */
    public static function issueJWSSerialized($user, array $custom = []): string
    {
        $jws = self::issueJWS($user, $custom);

        return self::serializeJWS($jws);
    }


    /**
     * Issue a JWS
     *
     * @param HasJWT $user The user who belongs the JWS.
     * @param array $custom
     *
     * @return JWS
     * @throws Exception
     */
    public static function issueJWS($user, array $custom = []): JWS
    {
        $jwk = self::getJWK();
        $jwsBuilder = new JWSBuilder(null, app()->make(AlgorithmManager::class));

        return $jwsBuilder->create()
            ->withPayload(self::getPayload($user, $custom))
            ->addSignature($jwk, [
                "typ" => "JWT",
                "alg" => class_basename(app()->make(Algorithm::class))
            ])
            ->build();
    }


    /**
     * Get the JWS payload.
     *
     * @param HasJWT $user The user who belongs the JWS.
     * @param array $custom
     *
     * @return string
     * @throws Exception
     */
    private static function getPayload($user, array $custom): string
    {
        $now = Carbon::now();
        $standard = [
            "iss" => config("jwt_auth.jwt.iss"),
            "sub" => $user->getSubject(),
            "aud" => config("jwt_auth.jwt.aud"),
            "exp" => $now->copy()->addMonth(3)->timestamp,
            "nbf" => $now->timestamp,
            "iat" => $now->timestamp,
            "jti" => Uuid::uuid4()
        ];
        $payload = array_replace_recursive($standard, $custom);

        return json_encode($payload);
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
}
