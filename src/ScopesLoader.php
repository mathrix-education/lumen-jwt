<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth;

use Illuminate\Support\Collection;
use function app;
use function preg_match;

class ScopesLoader
{
    /** @var Collection $routeScopes */
    private static $routeScopes;
    /** @var Collection $additionalScopes */
    private static $additionalScopes;
    /** @var Collection $loadedScopes */
    private static $loadedScopes;

    /**
     * Register additional scopes which may be not declared in routes
     *
     * @param array $scopes The additional scopes.
     */
    public static function registerAdditionalScopes(array $scopes)
    {
        self::$additionalScopes = Collection::make($scopes);
    }

    /**
     * Load the scopes declared in routes with the scope middleware.
     */
    private static function loadRouteScopes()
    {
        self::$routeScopes = Collection::make(app()->router->getRoutes())
            ->filter(static function (array $route) {
                return isset($route['action']['middleware']);
            })
            ->map(static function (array $route) {
                return $route['action']['middleware'];
            })
            ->map(static function (array $middleware) {
                $foundScope = null;

                Collection::make($middleware)->each(static function ($params) use (&$foundScope) {
                    preg_match('/scope:([a-z\-:]+)/', $params, $matches);
                    $foundScope = $matches[1] ?? null;
                });

                return $foundScope;
            })
            ->filter(static function (?string $scope) {
                return $scope !== null;
            })
            ->unique()
            ->values();
    }

    /**
     * Get the registered scopes of the application, including the additional scopes.
     *
     * @return array
     */
    public static function getRegisteredScopes()
    {
        if (!self::$loadedScopes) {
            self::loadRouteScopes();

            if (!self::$additionalScopes instanceof Collection) {
                self::$additionalScopes = Collection::make();
            }

            self::$loadedScopes = self::$routeScopes->merge(self::$additionalScopes)
                ->unique()
                ->sort()
                ->values();
        }

        return self::$loadedScopes->toArray();
    }
}
