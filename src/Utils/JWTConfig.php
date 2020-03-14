<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Utils;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\BindingResolutionException;
use Mathrix\Lumen\JWT\Exceptions\UnknownKeyConfig;
use Mathrix\Lumen\JWT\Exceptions\UnknownPayloadConfig;
use function config;
use function data_get;

class JWTConfig
{
    /**
     * @param string|null $name
     * @param string|null $path
     *
     * @return array|mixed
     *
     * @throws BindingResolutionException
     */
    public static function key(?string $name = null, ?string $path = null)
    {
        $name = $name ?? Container::getInstance()->make('config')->get('jwt.key');

        $config = config("jwt.keys.$name");

        if ($config === null) {
            throw new UnknownKeyConfig($name);
        }

        return data_get($config, $path);
    }

    /**
     * @param string|null $name
     * @param string|null $path
     *
     * @return array|mixed
     *
     * @throws BindingResolutionException
     */
    public static function payload(?string $name = null, ?string $path = null)
    {
        $name = $name ?? Container::getInstance()->make('config')->get('jwt.payload');

        $config = Container::getInstance()->make('config')->get("jwt.payloads.$name");

        if ($config === null) {
            throw new UnknownPayloadConfig($name);
        }

        return data_get($config, $path);
    }
}
