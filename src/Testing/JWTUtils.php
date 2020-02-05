<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use function app;
use function config;

/**
 * Collection of utilities.
 */
class JWTUtils
{
    /**
     * Overrides the current user resolver and globally set the user in the application.
     * Useful when testing the application.
     *
     * @param Authenticatable $user The user to impersonate.
     */
    public static function actingAs(Authenticatable $user): void
    {
        app()->make('auth')
            ->guard(config('jwt.guard'))
            ->setUser($user);
        app()->make('auth')
            ->shouldUse(config('jwt.guard'));
    }
}
