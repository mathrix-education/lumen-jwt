<?php

namespace App\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Auth\Exceptions\NotAuthenticatedException;

/**
 * Class LoggedMiddleware.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 0.9.3-dev
 */
class LoggedMiddleware
{
    public static $key = "logged";


    /**
     * @param Request $request
     * @param Closure $next
     *
     * @return mixed
     * @throws NotAuthenticatedException
     */
    public function handle(Request $request, Closure $next)
    {
        if ($request->user() === null) {
            throw new NotAuthenticatedException();
        }

        return $next($request);
    }
}
