<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Auth;

use Exception;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Auth\JWTUserResolver;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mockery;
use Sandbox\Models\User;

/**
 * @testdox JWT User Resolver
 * @coversDefaultClass \Mathrix\Lumen\JWT\Auth\JWTUserResolver
 */
class JWTUserResolverTest extends SandboxTestCase
{
    private function setupBuilderMock($sub, $res): void
    {
        $builder = Mockery::mock(Builder::class);
        $builder->shouldReceive('where')
            ->withArgs(['id', '=', $sub])
            ->andReturnSelf();
        $builder->shouldReceive('first')
            ->withNoArgs()
            ->andReturn($res);
        User::$builderMock = $builder;
    }

    private function getRequest(string $bearer): Request
    {
        return Request::create('/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $bearer,
        ]);
    }

    /**
     * @testdox extracts token from "Authorization" header and queries database using Eloquent
     * @covers ::__invoke
     * @throws Exception
     */
    public function testInvokeSuccess(): void
    {
        // Random data
        $sub = random_int(1, 999);
        $res = random_bytes(8);

        /** @var Driver $driver */
        $driver = app()->make(Driver::class);
        $bearer = $driver->signAndSerialize(['sub' => $sub]);

        $this->setupBuilderMock($sub, $res);
        $request = $this->getRequest($bearer);

        $this->assertEquals($res, (new JWTUserResolver())($request));
    }

    /**
     * @testdox do not identifies the user when there is no sub claim
     * @covers ::__invoke
     * @throws Exception
     */
    public function testInvokeNoSubClaim(): void
    {
        // Random data
        $sub = random_int(1, 999);

        /** @var Driver $driver */
        $driver = app()->make(Driver::class);
        $bearer = $driver->signAndSerialize(['not-sub' => $sub]);

        $request = $this->getRequest($bearer);

        $this->assertNull((new JWTUserResolver())($request));
    }

    /**
     * @testdox do not identifies the user when the signature is invalid
     * @covers ::__invoke
     * @throws Exception
     */
    public function testInvokeInvalidSignature(): void
    {
        // Random data
        $sub = random_int(1, 999);

        /** @var Driver $driver */
        $driver = app()->make(Driver::class);

        // Generate a token with an invalid signature
        $bearerOriginal = $driver->signAndSerialize(['sub' => $sub]);
        $bearer         = explode('.', $bearerOriginal);
        $bearer[2]      = base64_encode(random_bytes(strlen(base64_decode($bearer[2]))));
        $bearer         = implode('.', $bearer);

        $request = $this->getRequest($bearer);

        $this->assertNull((new JWTUserResolver())($request));
    }
}
