<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Throwable;

class InvalidCredentials extends JWTException
{
    public function __construct(?Throwable $previous = null, ?int $code = 0, array $headers = [])
    {
        parent::__construct('The given credentials were invalid', $previous, $code, $headers);
    }
}
