<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Utils;

use Mathrix\Lumen\JWT\Exceptions\UnknownKeyConfig;
use Mathrix\Lumen\JWT\Exceptions\UnknownPayloadConfig;
use function config;
use function data_get;

class JWTConfig
{
    public static function key(?string $name = null, ?string $path = null)
    {
        $name ??= config('jwt.key');

        $config = config("jwt.keys.$name");

        if ($config === null) {
            throw new UnknownKeyConfig($name);
        }

        return data_get($config, $path);
    }

    public static function payload(?string $name = null, ?string $path = null)
    {
        $name ??= config('jwt.payload');

        $config = config("jwt.payloads.$name");

        if ($config === null) {
            throw new UnknownPayloadConfig($name);
        }

        return data_get($config, $path);
    }
}
