<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Commands;

use Illuminate\Console\Command;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Drivers\DriverFactory;
use Mathrix\Lumen\JWT\Drivers\ECDSADriver;
use Mathrix\Lumen\JWT\Drivers\EdDSADriver;
use Mathrix\Lumen\JWT\Exceptions\InvalidConfiguration;

/**
 * Benchmark the signature and verification algorithms.
 */
class JWTBenchmarkCommand extends Command
{
    protected $signature   = 'jwt:benchmark {--iterations=100 : Number of iterations to run}';
    protected $description = 'Benchmark the signature and verification algorithms';

    private string $keyPath;
    private array  $results = [];

    public function handle(): void
    {
        $this->keyPath = storage_path('keychain/bench.json');
        $iterations    = (int)$this->option('iterations');

        $this->benchmark($this->getDriver(ES256::class, ECDSADriver::CURVE_P256), $iterations);
        $this->benchmark($this->getDriver(ES384::class, ECDSADriver::CURVE_P384), $iterations);
        $this->benchmark($this->getDriver(ES512::class, ECDSADriver::CURVE_P521), $iterations);
        $this->benchmark($this->getDriver(EdDSA::class, EdDSADriver::CURVE_ED25519), $iterations);
        $this->benchmark($this->getDriver(HS256::class, '256'), $iterations);
        $this->benchmark($this->getDriver(HS384::class, '384'), $iterations);
        $this->benchmark($this->getDriver(HS512::class, '512'), $iterations);
        $this->benchmark($this->getDriver(RS256::class, '2048'), $iterations);
        $this->benchmark($this->getDriver(RS384::class, '3072'), $iterations);
        $this->benchmark($this->getDriver(RS512::class, '4096'), $iterations);
        $this->benchmark($this->getDriver(PS256::class, '2048'), $iterations);
        $this->benchmark($this->getDriver(PS384::class, '3072'), $iterations);
        $this->benchmark($this->getDriver(PS512::class, '4096'), $iterations);

        $this->table([
            'Algorithm',
            'Signature (µs)',
            'Signatures / sec',
            'Verification (µs)',
            'Verifications / sec',
        ], $this->results);
    }

    /**
     * Remove the benchmark key.
     */
    private function removeKey(): void
    {
        if (file_exists($this->keyPath)) {
            unlink($this->keyPath);
        }
    }

    /**
     * Get the driver from the algorithm.
     *
     * @param string $algorithm   The algorithm class.
     * @param string $curveOrSize The curve (for ECDSA and EdDSA) or the key size in bits (HMAC and RSA).
     *
     * @return Driver|null
     */
    private function getDriver(string $algorithm, string $curveOrSize): ?Driver
    {
        try {
            $algorithm = DriverFactory::resolveAlgorithm($algorithm);
        } catch (InvalidConfiguration $e) {
            $this->line('Skipping ' . class_basename($algorithm));

            return null;
        }

        $this->line('Benchmarking ' . class_basename($algorithm));

        $config = [
            'algorithm' => $algorithm,
            'path'      => $this->keyPath,
        ];

        if (is_numeric($curveOrSize)) {
            $config['size'] = (int)$curveOrSize;
        } else {
            $config['curve'] = $curveOrSize;
        }

        $this->removeKey();

        return DriverFactory::from($config);
    }

    /**
     * Run a signature and verification benchmark for a given driver.
     *
     * @param Driver $driver     The driver to use for signature and verification.
     * @param int    $iterations The number of iterations.
     */
    private function benchmark(?Driver $driver, int $iterations): void
    {
        if ($driver === null) {
            // Do not run benchmark if driver is null.
            return;
        }

        $payloads = [];
        $tokens   = [];

        // Generate the payloads (does not count for timing measures)
        for ($i = 0; $i < $iterations; $i++) {
            $payloads[] = ['sub' => $i + 1];
        }

        // Signature benchmark start
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $tokens[] = $driver->signAndSerialize($payloads[$i]);
        }

        $inter = microtime(true); // Signature benchmark end / Verification benchmark start

        for ($i = 0; $i < $iterations; $i++) {
            $driver->verify($tokens[$i]);
        }

        $end = microtime(true); // Verification benchmark end

        $this->results[] = [
            'algorithm'  => class_basename($driver->getAlgorithm()),
            'sign_time'  => round((($inter - $start) / $iterations) * 1000 * 1000, 1), // µs
            'sign_freq'  => round($iterations / ($inter - $start), 1),
            'verif_time' => round((($end - $inter) / $iterations) * 1000 * 1000, 1), // µs
            'verif_freq' => round($iterations / ($end - $inter), 1),
        ];

        $this->removeKey();
    }
}
