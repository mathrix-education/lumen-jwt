<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Exceptions;

use InvalidArgumentException;
use Throwable;

/**
 * Thrown when the application tries to use a non-existing payload configuration.
 */
class UnknownPayloadConfig extends InvalidArgumentException
{
    public function __construct(string $name, ?Throwable $previous = null)
    {
        $message = <<<PAYLOAD
Unknown payload configuration `$name`. Did you forget to define it in your config/jwt.php? For instance:
config/jwt.php
[
    ...
    'payloads' => [
        '$name' => [
            'iss' => 'Your Issuer',
            'aud' => 'Your Audience',
            'exp' => '+1 day',
            'nbf' => 'now',
            'iat' => 'now',
            'jid' => 'uuid',
        ]
    ]
    ...
]
PAYLOAD;

        parent::__construct($message, 0, $previous);
    }
}
