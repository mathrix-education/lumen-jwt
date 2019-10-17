<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Mathrix\Lumen\Zero\Exceptions\Http\Http401Unauthorized;

class NotAuthenticated extends Http401Unauthorized
{
    protected $message = 'This route requires authentication.';
}
