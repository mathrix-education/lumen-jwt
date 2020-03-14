<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests;

use Illuminate\Support\Str;
use Mathrix\Lumen\JWT\Drivers\ECDSADriver;
use Mathrix\Lumen\JWT\Drivers\EdDSADriver;
use Mathrix\Lumen\JWT\Drivers\HMACDriver;
use Mathrix\Lumen\JWT\Drivers\RSADriver;
use function class_basename;
use function count;
use function file_exists;
use function storage_path;
use function str_replace;
use function unlink;

class DriverProvider
{
    /**
     * @param string $path
     *
     * @return bool
     */
    public static function deleteKeyIfExists(string $path): bool
    {
        if (file_exists($path)) {
            return unlink($path);
        }

        return true;
    }

    private static function withPath(array $dataset): array
    {
        foreach ($dataset as $name => $args) {
            $keyName = Str::slug(str_replace('|', '_', $name), '_');

            $dataset[$name]['path'] = storage_path("keychain/{$keyName}.json");
        }

        return $dataset;
    }

    public static function ecdsa(): array
    {
        $dataset = [];

        foreach (ECDSADriver::ALGORITHMS as $curveIndex => $algorithm) {
            $curve = ECDSADriver::CURVES[$curveIndex];

            $dataset['EC|' . class_basename($algorithm) . "|$curve"] = [
                'kty'       => 'EC',
                'algorithm' => $algorithm,
                'curve'     => $curve,
            ];
        }

        return self::withPath($dataset);
    }

    public static function eddsa(): array
    {
        $dataset = [];

        // EdDSA
        foreach (EdDSADriver::ALGORITHMS as $algorithm) {
            foreach (EdDSADriver::CURVES as $curve) {
                $dataset['OKP|' . class_basename($algorithm) . "|$curve"] = [
                    'kty'       => 'OKP',
                    'algorithm' => $algorithm,
                    'curve'     => $curve,
                ];
            }
        }

        return self::withPath($dataset);
    }

    public static function hmac(): array
    {
        $dataset = [];

        $hmSizes = ['256', '384', '512'];
        foreach (HMACDriver::ALGORITHMS as $algorithmIndex => $algorithm) {
            foreach ($hmSizes as $sizeIndex => $size) {
                if ($sizeIndex < $algorithmIndex) {
                    continue; // Do not allow shorter keys for strong algorithms
                }

                $dataset['oct|' . class_basename($algorithm) . "|$size"] = [
                    'kty'       => 'oct',
                    'algorithm' => $algorithm,
                    'size'      => $size,
                ];
            }
        }

        return self::withPath($dataset);
    }

    public static function rsa(): array
    {
        $dataset = [];

        $rsaSizes = ['2048', '3072', '4096'];
        foreach (RSADriver::ALGORITHMS as $sizeIndex => $algorithm) {
            $size = $rsaSizes[$sizeIndex % count($rsaSizes)];

            $dataset['RSA|' . class_basename($algorithm) . "|$size"] = [
                'kty'       => 'RSA',
                'algorithm' => $algorithm,
                'size'      => $size,
            ];
        }

        return self::withPath($dataset);
    }
}
