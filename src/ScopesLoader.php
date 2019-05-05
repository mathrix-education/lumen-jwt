<?php

namespace Mathrix\Lumen\JWT\Auth;

use Illuminate\Support\Collection;

/**
 * Class ScopesLoader.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
class ScopesLoader
{
    private static $loadedScopes;


    public static function getRegisteredScopes()
    {
        if (!is_array(self::$loadedScopes)) {
            self::loadScopes();
        }

        return self::$loadedScopes;
    }


    private static function loadScopes()
    {
        self::$loadedScopes = Collection::make(app()->router->getRoutes())
            ->filter(function (array $route) {
                return isset($route["action"]["middleware"]);
            })
            ->map(function (array $route) {
                return $route["action"]["middleware"];
            })
            ->map(function (array $middleware) {
                $foundScope = null;

                Collection::make($middleware)->each(function ($params) use (&$foundScope) {
                    preg_match('/scope:([a-z\-]+)/', $params, $matches);
                    $foundScope = $matches[1] ?? null;
                });

                return $foundScope;
            })
            ->filter(function (?string $scope) {
                return $scope !== null;
            })
            ->unique()
            ->sort()
            ->values()
            ->toArray();
    }
}
