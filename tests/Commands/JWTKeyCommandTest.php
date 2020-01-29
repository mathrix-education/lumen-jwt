<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests;

use Illuminate\Support\Facades\Artisan;
use Mathrix\Lumen\JWT\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Drivers\ECDSADriver;
use Mathrix\Lumen\JWT\Drivers\EdDSADriver;
use Mathrix\Lumen\JWT\Drivers\HMACDriver;
use Mathrix\Lumen\JWT\Drivers\RSADriver;
use stdClass;
use function file_get_contents;
use function json_decode;
use function storage_path;
use function strtolower;

/**
 * @testdox Artisan Command `jwt:key`
 * @coversDefaultClass \Mathrix\Lumen\JWT\Commands\JWTKeyCommand
 */
class JWTKeyCommandTest extends SandboxTestCase
{
    /**
     * Decode a generated JSON key.
     *
     * @param string $keyPath The key path.
     *
     * @return stdClass
     */
    private function decodeKey(string $keyPath): stdClass
    {
        return json_decode(file_get_contents($keyPath), false, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Generate the data for the data providers.
     *
     * @param array $dataset The dataset.
     *
     * @return array
     */
    private function generateProvider(array $dataset): array
    {
        return collect($dataset)
            ->mapWithKeys(fn($key) => [(string)$key => [$key]])
            ->toArray();
    }

    /**
     * @return array The data provider for the ECDSA.
     */
    public function handleECDSADataProvider(): array
    {
        return $this->generateProvider(ECDSADriver::CURVES);
    }

    /**
     * @return array The data provider for the EdDSA.
     */
    public function handleEdDSADataProvider(): array
    {
        return $this->generateProvider(EdDSADriver::CURVES);
    }

    /**
     * @return array The data provider for the HMAC.
     */
    public function handleHMACDataProvider(): array
    {
        return $this->generateProvider([512, 1024]);
    }

    /**
     * @return array The data provider for the RSA.
     */
    public function handleRSADataProvider(): array
    {
        return $this->generateProvider([1024, 2048, 3072, 4096]);
    }

    /**
     * @testdox      generates a key using ECDSA $curve curve.
     *
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
            '--type'  => ECDSADriver::NAME,
            '--path'  => $expectedKeyPath,
            '--curve' => $curve,
        ]);

        $this->assertFileExists($expectedKeyPath);
        $this->assertEquals('EC', $this->decodeKey($expectedKeyPath)->kty);
    }

    /**
     * @testdox      generates a key using EdDSA $curve curve.
     *
     * @param string $curve The Edwards Curve name.
     * @covers ::handle
     *
     * @dataProvider handleEdDSADataProvider
     */
    public function testHandleEdDSA(string $curve): void
    {
        $expectedKeyPath = storage_path('keychain/ed-' . strtolower($curve) . '.json');

        Artisan::call(JWTKeyCommand::class, [
            '--force' => '',
            '--type'  => EdDSADriver::NAME,
            '--path'  => $expectedKeyPath,
            '--curve' => $curve,
        ]);

        $this->assertFileExists($expectedKeyPath);
        $this->assertEquals('OKP', $this->decodeKey($expectedKeyPath)->kty);
    }

    /**
     * @testdox      generates an HMAC key of $size bits.
     *
     * @param int $size The HMAC key size in bits.
     *
     * @dataProvider handleHMACDataProvider
     * @covers ::handle
     */
    public function testHandleHMAC(int $size): void
    {
        $expectedKeyPath = storage_path("keychain/hmac-$size.json");

        Artisan::call(JWTKeyCommand::class, [
            '--force' => '',
            '--type'  => HMACDriver::NAME,
            '--path'  => $expectedKeyPath,
            '--size'  => $size,
        ]);

        $this->assertFileExists($expectedKeyPath);
        $this->assertEquals('oct', $this->decodeKey($expectedKeyPath)->kty);
    }

    /**
     * @testdox      generates a RSA key of $size bits.
     *
     * @param int $size The RSA key size in bits.
     *
     * @dataProvider handleRSADataProvider
     * @covers ::handle
     */
    public function testHandleRSA(int $size): void
    {
        $expectedKeyPath = storage_path("keychain/rsa-$size.json");

        Artisan::call(JWTKeyCommand::class, [
            '--force' => '',
            '--type'  => RSADriver::NAME,
            '--path'  => $expectedKeyPath,
            '--size'  => $size,
        ]);

        $this->assertFileExists($expectedKeyPath);
        $this->assertEquals('RSA', $this->decodeKey($expectedKeyPath)->kty);
    }
}
