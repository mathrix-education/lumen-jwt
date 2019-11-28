<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Throwable;

class InvalidJWT extends JWTException
{
    protected $message = 'The given JWT is invalid';

    public function __construct(?Throwable $previous = null, ?int $code = 0, array $headers = [])
    {
        parent::__construct('The given JWT is invalid', $previous, $code, $headers);
    }
}
