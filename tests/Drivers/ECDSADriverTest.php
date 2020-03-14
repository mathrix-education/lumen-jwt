<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Drivers;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use JsonException;
use Mathrix\Lumen\JWT\Drivers\ECDSADriver;
use Mathrix\Lumen\JWT\Tests\DriverProvider;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use function collect;

/**
 * @testdox ECDSA Driver
 * @coversDefaultClass \Mathrix\Lumen\JWT\Drivers\ECDSADriver
 */
class ECDSADriverTest extends SandboxTestCase
{
    public function configProvider(): array
    {
        return collect(DriverProvider::ecdsa())
            ->map(static function (array $config) {
                unset($config['kty'], $config['path']);

                return $config;
            })
            ->toArray();
    }

    /**
     * @param string $algorithm
     * @param string $curve
     *
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     *
     * @testdox      signs using $algorithm with the curve $curve
     * @dataProvider configProvider
     * @covers ::getSupportedAlgorithms
     * @covers ::getValidationRules
     * @covers ::generate
     * @covers ::postApply
     * @covers ::sign
     * @covers ::unserialize
     * @covers ::check
     * @covers ::verify
     */
    public function testSignCheckVerify(string $algorithm, string $curve): void
    {
        $driver = new ECDSADriver([
            'algorithm' => $algorithm,
            'curve'     => $curve,
        ]);

        $jws   = $driver->sign(['hello' => 'world'], false);
        $token = $driver->serialize($jws);
        $jws   = $driver->unserialize($token);

        $this->assertTrue($driver->check($jws));
        $this->assertTrue($driver->verify($jws));
    }
}
