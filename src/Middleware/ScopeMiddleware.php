<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Auth\Exceptions\MissingScope;

class ScopeMiddleware
{
    public static $key = 'scope';

    /**
     * Handle the incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param string  $scope   The required scope
     *
     * @return mixed
     *
     * @throws MissingScope
     */
    public function handle(Request $request, Closure $next, string $scope)
    {
        if ($request->user() === null || !$request->user()->hasScope($scope)) {
            throw new MissingScope($scope);
        }

        return $next($request);
    }
}
