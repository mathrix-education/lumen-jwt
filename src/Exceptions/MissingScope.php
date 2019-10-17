<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Mathrix\Lumen\Zero\Exceptions\Http\Http401Unauthorized;
use Throwable;

class MissingScope extends Http401Unauthorized
{
    public function __construct(string $scope, string $route, ?Throwable $previous = null)
    {
        parent::__construct([
            'scope' => $scope,
            'route' => $route,
        ], "$route: The scope $scope is required.", $previous);
    }
}
