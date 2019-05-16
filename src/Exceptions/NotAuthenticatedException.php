<?php

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Mathrix\Lumen\Zero\Exceptions\Http\Http401UnauthorizedException;

/**
 * Class NotAuthenticatedException.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 0.9.3-dev
 */
class NotAuthenticatedException extends Http401UnauthorizedException
{
    protected $message = "This route requires authentication.";
}
