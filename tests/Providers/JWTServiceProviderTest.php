<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Providers;

use Mathrix\Lumen\JWT\Config\JWTConfig;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Drivers\HMACDriver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Tests\TestsUtils;

/**
 * @testdox JWT Service Provider
 * @coversDefaultClass \Mathrix\Lumen\JWT\JWTServiceProvider
 */
class JWTServiceProviderTest extends SandboxTestCase
{
    /**
     * @testdox registers the Driver singleton
     */
    public function testSingleton(): void
    {
        $driver = $this->app->make(Driver::class);
        $this->assertInstanceOf(HMACDriver::class, $driver);
        TestsUtils::deleteKeyIfExists(JWTConfig::key('path'));
    }
}
