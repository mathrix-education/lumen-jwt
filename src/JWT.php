<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth;

use FastRoute\Dispatcher;
use FastRoute\RouteCollector;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use Mathrix\Lumen\Zero\Models\BaseModel;
use function app;
use function config;
use function explode;
use function FastRoute\simpleDispatcher;
use function forward_static_call_array;
use function mb_strtoupper;
use function str_replace;

class JWT
{
    public const ECDSA_TYPE = 'ecdsa';
    public const RSA_TYPE   = 'rsa';
    public const CURVE_P256 = 'P-256';
    public const CURVE_P384 = 'P-384';
    public const CURVE_P521 = 'P-521';

    /** @var Dispatcher $dispatcher */
    private static $dispatcher;

    /**
     * Get a user with valid scopes for the given method and uri.
     *
     * @param string $method
     * @param string $uri
     *
     * @return BaseModel
     */
    public static function autoScope(string $method, string $uri)
    {
        $scopes = self::getScopes($method, $uri);

        return self::withScopes(...$scopes);
    }

    /**
     * Get scopes associated with a route.
     *
     * @param string $method
     * @param string $uri
     *
     * @return array|null
     */
    private static function getScopes(string $method, string $uri): ?array
    {
        $result = self::dispatch($method, $uri);

        if ($result[0] === Dispatcher::FOUND && !empty($result[1]['middleware'])) {
            foreach ($result[1]['middleware'] as $middleware) {
                if (Str::startsWith($middleware, 'scope:')) {
                    $scopes = str_replace('scope:', '', $middleware);

                    return explode(',', $scopes);
                }
            }
        }

        return [];
    }

    /**
     * Dispatch an uri.
     *
     * @param string $method The method.
     * @param string $uri    The uri.
     *
     * @return array
     */
    private static function dispatch(string $method, string $uri): array
    {
        $method = mb_strtoupper($method);

        return self::makeDispatcher()->dispatch($method, $uri);
    }

    /**
     * Get the Dispatcher
     *
     * @return Dispatcher
     */
    private static function makeDispatcher(): Dispatcher
    {
        if (!self::$dispatcher instanceof Dispatcher) {
            self::$dispatcher = simpleDispatcher(static function (RouteCollector $r) {
                foreach (app()->router->getRoutes() as $route) {
                    $r->addRoute($route['method'], $route['uri'], $route['action']);
                }
            });
        }

        return self::$dispatcher;
    }

    /**
     * Get a user with valid scopes for the given method and uri.
     *
     * @param array $scopes
     *
     * @return Authenticatable|BaseModel
     */
    public static function withScopes(...$scopes)
    {
        /** @var Builder $query */
        $query = forward_static_call_array([config('jwt_auth.user_model'), 'query'], []);
        /** @var Authenticatable|BaseModel $user */
        $user = $query->inRandomOrder()->firstOrFail();
        $user->setAttribute('scopes', $scopes);
        $user->save();

        self::actingAs($user);

        return $user;
    }

    /**
     * Overrides the current user resolver and globally set the user in the application.
     * It is really useful for tests.
     *
     * @param Authenticatable|BaseModel $user
     */
    public static function actingAs($user)
    {
        $user->refresh();

        app()->make('auth')
            ->guard(config('jwt_auth.guard'))
            ->setUser($user);
        app()->make('auth')
            ->shouldUse(config('jwt_auth.guard'));
    }
}
