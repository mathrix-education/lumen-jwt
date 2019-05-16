<?php

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Mathrix\Lumen\Zero\Exceptions\Http\Http401UnauthorizedException;

/**
 * Class InvalidCredentialsException.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since
 */
class InvalidCredentialsException extends Http401UnauthorizedException
{
    protected $message = "The given credentials were invalid.";
}
