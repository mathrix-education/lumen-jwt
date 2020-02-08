<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Drivers;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use JsonException;
use Mathrix\Lumen\JWT\Drivers\RSADriver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Tests\DriverProvider;
use function collect;

/**
 * @testdox RSA Driver
 * @coversDefaultClass \Mathrix\Lumen\JWT\Drivers\RSADriver
 */
class RSADriverTest extends SandboxTestCase
{
    public function configProvider(): array
    {
        return collect(DriverProvider::rsa())
            ->map(static function (array $config) {
                unset($config['kty'], $config['path']);
                $config['size'] = (int)$config['size'];

                return $config;
            })
            ->toArray();
    }

    /**
     * @param string $algorithm
     * @param int    $size
     *
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     * @throws JsonException
     *
     * @testdox      signs using $algorithm with the key size of $size bits
     * @dataProvider configProvider
     * @covers ::getSupportedAlgorithms
     * @covers ::getMinimumKeySize
     * @covers ::getValidationRules
     * @covers ::generate
     * @covers ::postApply
     * @covers ::sign
     * @covers ::unserialize
     * @covers ::check
     * @covers ::verify
     */
    public function testSignCheckVerify(string $algorithm, int $size): void
    {
        $driver = new RSADriver([
            'algorithm' => $algorithm,
            'size'      => $size,
        ]);

        $jws   = $driver->sign(['hello' => 'world'], false);
        $token = $driver->serialize($jws);
        $jws   = $driver->unserialize($token);

        $this->assertTrue($driver->check($jws));
        $this->assertTrue($driver->verify($jws));
    }
}
