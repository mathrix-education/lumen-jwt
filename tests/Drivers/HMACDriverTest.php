<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Drivers;

use Mathrix\Lumen\JWT\Drivers\HMACDriver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Tests\TestsUtils;

/**
 * @testdox HMAC Driver
 * @coversDefaultClass \Mathrix\Lumen\JWT\Drivers\ECDSADriver
 */
class HMACDriverTest extends SandboxTestCase
{
    private HMACDriver $instance;

    public function configProvider(): array
    {
        return collect(TestsUtils::hmac())
            ->map(static function (array $config) {
                unset($config['kty']);

                return $config;
            })
            ->toArray();
    }

    public function init(string $algorithm, string $size, string $path): void
    {
        $this->instance = new HMACDriver([
            'algorithm' => $algorithm,
            'size'      => (int)$size,
            'path'      => $path,
        ]);
    }

    /**
     * @testdox      signs using $algorithm with the key size of $size bits
     * @dataProvider configProvider
     *
     * @param string $algorithm
     * @param string $size
     * @param string $path
     */
    public function testSignCheckVerify(string $algorithm, string $size, string $path): void
    {
        TestsUtils::deleteKeyIfExists($path);
        $this->init($algorithm, $size, $path);

        $payload = [
            'hello' => 'world',
        ];

        $jwt = $this->instance->signAndSerialize($payload);
        $jws = $this->instance->unserialize($jwt);
        $this->assertTrue($this->instance->check($jws));
        $this->assertTrue($this->instance->verify($jws));
        TestsUtils::deleteKeyIfExists($path);
    }
}
