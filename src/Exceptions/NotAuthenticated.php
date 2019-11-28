<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Throwable;

class NotAuthenticated extends JWTException
{
    protected $message = 'This route requires authentication.';

    public function __construct(?Throwable $previous = null)
    {
        parent::__construct('This route requires authentication.', $previous);
    }
}
