<?php

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Mathrix\Lumen\Zero\Exceptions\Http\Http401UnauthorizedException;

/**
 * Class InvalidJWTException.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
class InvalidJWTException extends Http401UnauthorizedException
{
    protected $message = "The given JWT is invalid";
}
