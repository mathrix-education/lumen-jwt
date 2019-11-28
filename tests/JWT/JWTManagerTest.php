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
    /**
     * @return JWTManager
     */
    private function getMock()
    {
        return $this->getMockForAbstractClass(JWTManager::class);
    }

    public function testGetJWKPath(): void
    {
        $this->assertIsString($this->getMock()->getJWKPath());
    }

    public function testGetJWKPublic(): void
    {
        /** @var JWK $jwk */
        $jwk = $this->getMock()->getJWKPublic();
        $this->assertFalse(isset($jwk->jsonSerialize()['d']));
    }
}
