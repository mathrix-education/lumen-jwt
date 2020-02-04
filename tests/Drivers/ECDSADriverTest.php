<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Drivers;

use Mathrix\Lumen\JWT\Drivers\ECDSADriver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Tests\TestsUtils;

/**
 * @testdox ECDSA Driver
 * @coversDefaultClass \Mathrix\Lumen\JWT\Drivers\ECDSADriver
 */
class ECDSADriverTest extends SandboxTestCase
{
    private ECDSADriver $instance;

    public function configProvider(): array
    {
        return collect(TestsUtils::ecdsa())
            ->map(static function (array $config) {
                unset($config['kty']);

                return $config;
            })
            ->toArray();
    }

    public function init(string $algorithm, string $curve, string $path): void
    {
        $this->instance = new ECDSADriver([
            'algorithm' => $algorithm,
            'curve'     => $curve,
            'path'      => $path,
        ]);
    }

    /**
     * @testdox      signs using $algorithm with the curve $curve
     * @dataProvider configProvider
     *
     * @param string $algorithm
     * @param string $curve
     * @param string $path
     */
    public function testSignCheckVerify(string $algorithm, string $curve, string $path): void
    {
        TestsUtils::deleteKeyIfExists($path);
        $this->init($algorithm, $curve, $path);

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
