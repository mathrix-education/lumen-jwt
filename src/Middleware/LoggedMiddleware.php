<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Auth\Exceptions\NotAuthenticated;

class LoggedMiddleware
{
    public static $key = 'logged';

    /**
     * @param Request $request
     * @param Closure $next
     *
     * @return mixed
     *
     * @throws NotAuthenticated
     */
    public function handle(Request $request, Closure $next)
    {
        if ($request->user() === null) {
            throw new NotAuthenticated();
        }

        return $next($request);
    }
}
