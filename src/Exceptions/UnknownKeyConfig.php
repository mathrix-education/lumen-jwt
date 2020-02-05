<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Exceptions;

use InvalidArgumentException;
use Throwable;

/**
 * Thrown when the application tries to use a non-existing key configuration.
 */
class UnknownKeyConfig extends InvalidArgumentException
{
    public function __construct(string $name, ?Throwable $previous = null)
    {
        $message = <<<PAYLOAD
        Unknown key configuration `$name`. Did you forget to define it in your config/jwt.php? For instance:
        config/jwt.php
        [
            ...
            'keys' => [
                '$name' => [
                    'algorithm' => 'HS512',
                    'size'      => 1024,
                    'path'      => storage_path('keychain/jwt_auth.json'),
                ]
            ]
            ...
        ]
        PAYLOAD;

        parent::__construct($message, 0, $previous);
    }
}
