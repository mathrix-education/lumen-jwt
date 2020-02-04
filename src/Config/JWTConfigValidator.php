<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Config;

use Mathrix\Lumen\JWT\Drivers\DriverFactory;
use Mathrix\Lumen\JWT\Exceptions\InvalidConfiguration;

/**
 *
 */
class JWTConfigValidator
{
    public function algorithm(string $algorithm, array $allowed): string
    {
        $algorithm = DriverFactory::resolveAlgorithm($algorithm);

        if (!in_array($algorithm, $allowed, true)) {
            throw InvalidConfiguration::invalidAlgorithm($algorithm, $allowed);
        }

        return $algorithm;
    }

    public function assertKeyReadable(string $keyPath): bool
    {
        if (file_exists($keyPath)) {
            if (is_readable($keyPath)) {
                return true;
            }

            throw InvalidConfiguration::keyReadable($keyPath);
        }

        return $this->assertKeyReadable(dirname($keyPath));
    }

    public function assertKeyWritable(string $keyPath): bool
    {
        if (file_exists($keyPath)) {
            if (is_writable($keyPath)) {
                return true;
            }

            throw InvalidConfiguration::keyWritable($keyPath);
        }

        return $this->assertKeyWritable(dirname($keyPath));
    }
}
