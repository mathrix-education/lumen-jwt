<?php

namespace Mathrix\Lumen\JWT\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Auth\Exceptions\MissingScopeException;
use Mathrix\Lumen\Zero\Exceptions\Http\Http401UnauthorizedException;

/**
 * Class ScopeMiddleware.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
class ScopeMiddleware
{
    public static $key = "scope";


    /**
     * Handle the incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param string $scope The required scope
     *
     * @return mixed
     *
     * @throws MissingScopeException
     * @throws Http401UnauthorizedException
     */
    public function handle(Request $request, Closure $next, string $scope)
    {
        if ($request->user() === null || !$request->user()->hasScope($scope)) {
            throw new MissingScopeException($scope, $request->url());
        }

        return $next($request);
    }
}
