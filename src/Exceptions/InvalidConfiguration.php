<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Exceptions;

use InvalidArgumentException;

/**
 *
 */
class InvalidConfiguration extends InvalidArgumentException
{
    private static function makeMessage(string $message, string $config = null): string
    {
        $config ??= config('jwt.key');

        return "Invalid key configuration `{$config}`: {$message}";
    }

    public static function missingKeys(array $missing, string $config = null): InvalidConfiguration
    {
        $message = self::makeMessage('missing ' . implode(', ', $missing), $config);

        return new self($message);
    }

    public static function missingLib(string $algorithm, string $library, string $config = null): InvalidConfiguration
    {
        $message = self::makeMessage("you need to install {$library} in order to use {$algorithm}", $config);

        return new self($message);
    }

    public static function invalidAlgorithm(string $algorithm, array $allowed = [], string $config = null):
    InvalidConfiguration {
        if (empty($allowed)) {
            $message = self::makeMessage("unknown algorithm $algorithm", $config);
        } else {
            $message = self::makeMessage(
                "found $algorithm which is not in " . implode(', ', $allowed),
                $config
            );
        }

        return new self($message);
    }

    public static function keyReadable(string $path, string $config = null): InvalidConfiguration
    {
        $message = self::makeMessage("cannot read the key at path $path", $config);

        return new self($message);
    }

    public static function keyWritable(string $path, string $config = null): InvalidConfiguration
    {
        $message = self::makeMessage("cannot write the key at path $path", $config);

        return new self($message);
    }
}
