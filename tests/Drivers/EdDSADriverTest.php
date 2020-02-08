<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Drivers;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use JsonException;
use Mathrix\Lumen\JWT\Drivers\EdDSADriver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Tests\DriverProvider;
use function collect;

/**
 * @testdox EdDSA Driver
 * @coversDefaultClass \Mathrix\Lumen\JWT\Drivers\EdDSADriver
 */
class EdDSADriverTest extends SandboxTestCase
{
    private EdDSADriver $instance;

    public function configProvider(): array
    {
        return collect(DriverProvider::eddsa())
            ->map(static function (array $config) {
                unset($config['kty']);

                return $config;
            })
            ->toArray();
    }

    /**
     * @param string $algorithm
     * @param string $curve
     * @param string $path
     *
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     * @throws JsonException
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
    public function testSignCheckVerify(string $algorithm, string $curve, string $path): void
    {
        $driver = new EdDSADriver([
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
