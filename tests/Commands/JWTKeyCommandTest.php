<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Tests;

use Illuminate\Support\Facades\Artisan;
use Mathrix\Lumen\JWT\Auth\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Auth\JWT;
use function file_get_contents;
use function json_decode;
use function storage_path;
use function strtolower;

/**
 * @coversDefaultClass \Mathrix\Lumen\JWT\Auth\Commands\JWTKeyCommand
 */
class JWTKeyCommandTest extends SandboxTestCase
{
    public function handleECDSADataProvider(): array
    {
        return [
            'p256' => [JWT::CURVE_P256],
            'p384' => [JWT::CURVE_P384],
            'p521' => [JWT::CURVE_P521],
        ];
    }

    /**
     * @param string $curve The Elliptic Curve
     *
     * @covers ::handle
     * @dataProvider handleECDSADataProvider
     */
    public function testHandleECDSA(string $curve): void
    {
        $expectedKeyPath = storage_path('keychain/ec-' . strtolower($curve) . '.json');

        Artisan::call(JWTKeyCommand::class, [
            '--force' => '',
            '--type'  => JWT::ECDSA_TYPE,
            '--path'  => $expectedKeyPath,
            '--curve' => $curve,
        ]);

        $this->assertFileExists($expectedKeyPath);
        $key = json_decode(file_get_contents($expectedKeyPath));
        $this->assertEquals('EC', $key->kty);
        $this->assertEquals($curve, $key->crv);
    }

    /**
     * @covers ::handle
     */
    public function testHandleRSA(): void
    {
        $expectedKeyPath = storage_path('keychain/rsa-4096.json');

        Artisan::call(JWTKeyCommand::class, [
            '--force' => '',
            '--type'  => JWT::RSA_TYPE,
            '--path'  => $expectedKeyPath,
            '--size'  => 4096,
        ]);

        $this->assertFileExists($expectedKeyPath);
        $key = json_decode(file_get_contents($expectedKeyPath));
        $this->assertEquals('RSA', $key->kty);
    }
}
