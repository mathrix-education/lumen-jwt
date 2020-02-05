<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Config;

use function config;

class JWTConfig
{
    public static function key($path = null, $default = null)
    {
        $name = config('jwt.key');
        $path = "jwt.keys.$name" . ($path !== null ? ".$path" : '');

        return config($path, $default);
    }

    public static function payload($path = null, $default = null)
    {
        $name = config('jwt.payload');
        $path = "jwt.payloads.$name" . ($path !== null ? ".$path" : '');

        return config($path, $default);
    }
}
