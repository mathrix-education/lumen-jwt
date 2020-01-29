<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Utils;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Collection of utilities.
 */
class JWTUtils
{
    /**
     * Overrides the current user resolver and globally set the user in the application.
     * Useful when testing the application.
     *
     * @param Authenticatable|Model $user The user to impersonate.
     */
    public static function actingAs($user): void
    {
        $user->refresh();

        app()->make('auth')
            ->guard(config('jwt.guard'))
            ->setUser($user);
        app()->make('auth')
            ->shouldUse(config('jwt.guard'));
    }
}
