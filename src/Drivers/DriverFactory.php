<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

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
use Mathrix\Lumen\JWT\Exceptions\InvalidConfiguration;

/**
 *
 */
class DriverFactory
{
    public const ALGORITHM_NAMESPACE = 'Jose\\Component\\Signature\\Algorithm';

    /**
     * Instantiate a driver from a configuration.
     *
     * @param array $config The driver configuration.
     *
     * @return ECDSADriver|EdDSADriver|HMACDriver|RSADriver
     */
    public static function from(array $config)
    {
        $algorithm = self::resolveAlgorithm($config['algorithm']);

        $drivers = [ECDSADriver::class, EdDSADriver::class, HMACDriver::class, RSADriver::class];

        /** @var ECDSADriver|EdDSADriver|HMACDriver|RSADriver $driver */
        foreach ($drivers as $driver) {
            if (in_array($algorithm, $driver::ALGORITHMS, true)) {
                return new $driver($config);
            }
        }
    }

    public static function resolveAlgorithm(string $algorithm): string
    {
        if (class_exists($algorithm)) {
            return $algorithm;
        }

        $fqcAlgorithm = self::ALGORITHM_NAMESPACE . "\\$algorithm";

        if (class_exists($fqcAlgorithm)) {
            return $fqcAlgorithm;
        }

        switch ($fqcAlgorithm) {
            case ES256::class:
            case ES384::class:
            case ES512::class:
                $missingLib = 'web-token/jwt-signature-algorithm-ecdsa';
                break;
            case EdDSA::class:
                $missingLib = 'web-token/jwt-signature-algorithm-eddsa';
                break;
            case HS256::class:
            case HS384::class:
            case HS512::class:
                $missingLib = 'web-token/jwt-signature-algorithm-hmac';
                break;
            case RS256::class:
            case RS384::class:
            case RS512::class:
            case PS256::class:
            case PS384::class:
            case PS512::class:
                $missingLib = 'web-token/jwt-signature-algorithm-rsa';
                break;
            default:
                $missingLib = null;
                break;
        }

        if ($missingLib) {
            throw InvalidConfiguration::missingLib($algorithm, $missingLib);
        }

        throw InvalidConfiguration::invalidAlgorithm($algorithm);
    }
}
