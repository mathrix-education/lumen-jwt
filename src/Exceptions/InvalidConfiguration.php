<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Exceptions;

use InvalidArgumentException;
use Jose\Component\Core\Algorithm;

/**
 *
 */
class InvalidConfiguration extends InvalidArgumentException
{
    private static function message(string $message, string $config = null)
    {
        $config ??= config('jwt.key');

        return 'Invalid key configuration "' . $config ?? config('jwt.key') . '": ' . $message;
    }

    public static function missing(array $missing, string $config = null): InvalidConfiguration
    {
        $message = self::message('missing ' . implode(', ', $missing), $config);

        return new self($message);
    }

    public static function algorithm(string $algorithm, string $config = null): InvalidConfiguration
    {
        $message = self::message(
            "found algorithm $algorithm which is not implementing %s." . Algorithm::class,
            $config
        );

        return new self($message);
    }

    public static function keyReadable(string $path, string $config = null): InvalidConfiguration
    {
        $message = self::message("cannot read the key at path $path", $config);

        return new self($message);
    }

    public static function keyWritable(string $path, string $config = null): InvalidConfiguration
    {
        $message = self::message("cannot write the key at path $path", $config);

        return new self($message);
    }
}
