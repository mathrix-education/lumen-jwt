<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Drivers\Driver;

/**
 *
 */
class JWTCheckMiddleware
{
    public const NAME = 'jwt.check';
    /** @var Driver $driver */
    private Driver $driver;

    public function __construct(Driver $driver)
    {
        $this->driver = $driver;
    }

    public function handle(Request $request, Closure $next)
    {
        $bearerToken = $request->bearerToken();

        if ($bearerToken !== null) {
            $this->driver->check($bearerToken);
        }

        return $next($request);
    }
}
