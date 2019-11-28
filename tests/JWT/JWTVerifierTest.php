<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Tests\JWT;

use Mathrix\Lumen\JWT\Auth\HasJWT;
use Mathrix\Lumen\JWT\Auth\JWT\JWTIssuer;
use Mathrix\Lumen\JWT\Auth\JWT\JWTVerifier;
use Mathrix\Lumen\JWT\Auth\Tests\SandboxTestCase;
use Mockery;

/**
 * @coversDefaultClass \Mathrix\Lumen\JWT\Auth\JWT\JWTVerifier
 */
class JWTVerifierTest extends SandboxTestCase
{
    /**
     * @covers ::verify
     */
    public function testVerify()
    {
        /** @var HasJWT|Mockery\MockInterface $user */
        $user = Mockery::mock(HasJWT::class);
        $user->shouldReceive('getKey')->withNoArgs()->andReturn(1);
        /** @var JWTIssuer $issuer */
        $issuer = $this->app->make(JWTIssuer::class);
        $token  = $issuer->issueJWSSerialized($user);

        /** @var JWTVerifier $verifier */
        $verifier = $this->app->make(JWTVerifier::class);
        $this->assertTrue($verifier->verify($token));
    }
}
