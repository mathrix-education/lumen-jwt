<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\JWT;

use Carbon\Carbon;
use Illuminate\Support\Str;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\Serializer;
use Mathrix\Lumen\JWT\Auth\HasJWT;
use function app;
use function array_replace_recursive;
use function class_basename;
use function config;
use function json_encode;

/**
 * Allow application to issue JWT.
 */
class JWTIssuer extends JWTManager
{
    /**
     * Get the JWS payload.
     *
     * @param HasJWT $user   The user who belongs the JWS.
     * @param array  $custom The custom JWT payload.
     *
     * @return string
     */
    private function getPayload($user, array $custom): string
    {
        $now  = Carbon::now();
        $uuid = Str::uuid()->toString();

        /** @var array $standard The standard payload. */
        $standard = [
            'iss' => config('jwt_auth.jwt.iss'),
            'sub' => $user->getSubject(),
            'aud' => config('jwt_auth.jwt.aud'),
            'exp' => $now->copy()
                ->addUnit(
                    config('jwt_auth.expiration.unit'),
                    config('jwt_auth.expiration.value')
                )
                ->timestamp,
            'nbf' => $now->timestamp,
            'iat' => $now->timestamp,
            'jti' => $uuid,
        ];
        $payload  = array_replace_recursive($standard, $custom);

        return json_encode($payload);
    }

    /**
     * Issue a JWS.
     *
     * @param HasJWT $user   The user who belongs the JWS.
     * @param array  $custom The custom JWT payload.
     *
     * @return JWS
     */
    public function issueJWS($user, array $custom = []): JWS
    {
        $jwk        = $this->getJWK();
        $jwsBuilder = new JWSBuilder(app()->make(AlgorithmManager::class));

        return $jwsBuilder->create()
            ->withPayload($this->getPayload($user, $custom))
            ->addSignature($jwk, [
                'typ' => 'JWT',
                'alg' => class_basename(app()->make(Algorithm::class)),
            ])
            ->build();
    }

    /**
     * Serialize an existing JWS.
     *
     * @param JWS $jws The JWS.
     *
     * @return string
     */
    public function serializeJWS(JWS $jws)
    {
        /** @var Serializer $serializer */
        $serializer = app()->make(Serializer::class);

        return $serializer->serialize($jws);
    }

    /**
     * Issue a serialized JWS.
     *
     * @param HasJWT $user   The user who belongs the JWS.
     * @param array  $custom The custom JWT payload.
     *
     * @return string The serialized JWS.
     */
    public function issueJWSSerialized($user, array $custom = []): string
    {
        $jws = $this->issueJWS($user, $custom);

        return $this->serializeJWS($jws);
    }
}
