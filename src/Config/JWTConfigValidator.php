<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Config;

use Mathrix\Lumen\JWT\Exceptions\InvalidConfiguration;

/**
 *
 */
class JWTConfigValidator
{
    private const ALGORITHM_NAMESPACE = 'Jose\\Component\\Signature\\Algorithm';

    public function algorithm(string $algorithm, array $allowed): string
    {
        if (!class_exists($algorithm)) {
            $algorithm = self::ALGORITHM_NAMESPACE . "\\$algorithm";
        }

        if (!class_exists($algorithm) || !in_array($algorithm, $allowed, true)) {
            throw InvalidConfiguration::algorithm($algorithm);
        }

        return $algorithm;
    }

    public function isKeyReadable(string $keyPath): bool
    {
        if (file_exists($keyPath)) {
            if (is_readable($keyPath)) {
                return true;
            }

            throw InvalidConfiguration::keyReadable($keyPath);
        }

        return $this->isKeyReadable(dirname($keyPath));
    }

    public function isKeyWritable(string $keyPath): bool
    {
        if (file_exists($keyPath)) {
            if (is_writable($keyPath)) {
                return true;
            }

            throw InvalidConfiguration::keyWritable($keyPath);
        }

        return $this->isKeyWritable(dirname($keyPath));
    }
}
