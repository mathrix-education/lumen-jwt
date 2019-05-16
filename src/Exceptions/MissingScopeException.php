<?php

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Mathrix\Lumen\Zero\Exceptions\Http\Http401UnauthorizedException;
use Throwable;

/**
 * Class MissingScopeException.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
class MissingScopeException extends Http401UnauthorizedException
{
    public function __construct(string $scope, string $route, Throwable $previous = null)
    {
        parent::__construct([
            "scope" => $scope,
            "route" => $route
        ], "$route: The scope $scope is required.", $previous);
    }
}
