<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests;

use Illuminate\Support\Facades\Artisan;
use Mathrix\Lumen\JWT\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Utils\JWTConfig;
use stdClass;
use function array_merge;
use function file_get_contents;
use function fileperms;
use function is_numeric;
use function is_string;
use function json_decode;
use function md5;
use function octdec;
use function sprintf;
use function substr;
use const JSON_THROW_ON_ERROR;

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
     * Generate the arguments for the `jwt:key` command.
     *
     * @return array
     */
    public function handleProvider(): array
    {
        return array_merge(
            DriverProvider::ecdsa(),
            DriverProvider::eddsa(),
            DriverProvider::hmac(),
            DriverProvider::rsa()
        );
    }

    /**
     * @param string $kty
     * @param string $algorithm
     * @param string $curveOrSize
     * @param string $path
     *
     * @testdox      generates a $kty key using $algorithm ($curveOrSize)
     * @covers ::handle
     * @dataProvider handleProvider
     */
    public function testHandle(string $kty, string $algorithm, string $curveOrSize, string $path): void
    {
        $args = [
            '--force'     => '',
            '--algorithm' => $algorithm,
            '--path'      => $path,
        ];
        if (is_numeric($curveOrSize)) {
            $args['--size'] = $curveOrSize;
        } elseif (is_string($curveOrSize)) {
            $args['--curve'] = $curveOrSize;
        } else {
            $this->fail('Invalid curveOrSize parameter, got ' . $curveOrSize . ', expected string or integer');
        }

        DriverProvider::deleteKeyIfExists($path);
        Artisan::call(JWTKeyCommand::class, $args);

        $this->assertFileExists($path);
        $actualPermissions = octdec(substr(sprintf('%o', fileperms($path)), -4));
        $this->assertEquals(Driver::KEY_PERMS, $actualPermissions);
        $this->assertEquals($kty, $this->decodeKey($path)->kty);
        DriverProvider::deleteKeyIfExists($path);
    }

    /**
     * @testdox do not override existing key without the --force flag
     * @covers ::handle
     */
    public function testSafeOverride(): void
    {
        $path = JWTConfig::key(null, 'path');
        DriverProvider::deleteKeyIfExists($path);

        $this->artisan('jwt:key'); // Generate a key at $path
        $this->assertFileExists($path);

        $md5  = md5(file_get_contents($path)); // Get the md5 of the generated key
        $exit = $this->artisan('jwt:key');
        $this->assertEquals(1, $exit);
        $this->assertEquals($md5, md5(file_get_contents($path))); // Check if the key has changed
        DriverProvider::deleteKeyIfExists($path);
    }
}
