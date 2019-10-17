<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Tests\JWT;

use Jose\Component\Core\JWK;
use Mathrix\Lumen\JWT\Auth\JWT\JWTManager;
use Mathrix\Lumen\JWT\Auth\Tests\SandboxTestCase;
use Mathrix\Lumen\Zero\Testing\Traits\Reflector;
use ReflectionException;

/**
 * @coversDefaultClass \Mathrix\Lumen\JWT\Auth\JWT\JWTManager
 */
class JWTManagerTest extends SandboxTestCase
{
    use Reflector;

    /**
     * @return JWTManager
     */
    private function getMock()
    {
        return $this->getMockForAbstractClass(JWTManager::class);
    }

    /**
     * @covers ::getJWKPath
     */
    public function testGetJWKPath(): void
    {
        $this->assertIsString($this->getMock()->getJWKPath());
    }

    /**
     * @throws ReflectionException
     *
     * @covers ::getJWK
     */
    public function testGetJWK(): void
    {
        $mock = $this->getMock();
        /** @var JWK $jwk */
        $jwk = $this->reflectInvoke($mock, 'getJWK');
        $this->assertNotEmpty($jwk->jsonSerialize()['d']); // Assert private key exists
    }

    /**
     * @covers ::getJWKPublic
     */
    public function testGetJWKPublic(): void
    {
        /** @var JWK $jwk */
        $jwk = $this->getMock()->getJWKPublic();
        $this->assertFalse(isset($jwk->jsonSerialize()['d']));
    }
}
