<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Throwable;

abstract class JWTException extends UnauthorizedHttpException
{
    public function __construct(string $message, ?Throwable $previous = null, ?int $code = 0, array $headers = [])
    {
        parent::__construct('Bearer', $message, $previous, $code, $headers);
    }
}
