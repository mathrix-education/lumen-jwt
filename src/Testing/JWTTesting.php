<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use function app;
use function config;

/**
 * Collection of utilities.
 */
class JWTTesting
{
    /**
     * Overrides the current user resolver and globally set the user in the application.
     * Useful when testing the application.
     *
     * @param Authenticatable $user  The user to impersonate.
     * @param string|null     $guard The guard to use.
     */
    public static function actingAs(Authenticatable $user, ?string $guard = null): void
    {
        app()->make('auth')
            ->shouldUse($guard ?? config('jwt.auth.driver_name'));
        app()->make('auth')
            ->guard($guard ?? config('jwt.auth.driver_name'))
            ->setUser($user);
    }
}
