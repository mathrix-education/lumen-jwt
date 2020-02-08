<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Providers;

use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Drivers\HMACDriver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use function config;

/**
 * @testdox JWT Service Provider
 * @coversDefaultClass \Mathrix\Lumen\JWT\JWTServiceProvider
 */
class JWTServiceProviderTest extends SandboxTestCase
{
    /**
     * @testdox registers the Driver singleton
     * @covers ::register
     */
    public function testSingleton(): void
    {
        config([
            'jwt.key'            => 'singleton',
            'jwt.keys.singleton' => [
                'algorithm' => 'HS512',
                'size'      => 512,
            ],
        ]);

        $driver = $this->app->make(Driver::class);
        $this->assertInstanceOf(HMACDriver::class, $driver);
    }
}
