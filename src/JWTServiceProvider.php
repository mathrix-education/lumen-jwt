<?php

namespace Mathrix\Lumen\JWT\Auth;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\Serializer;
use Laravel\Lumen\Application;
use Mathrix\Lumen\JWT\Auth\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Auth\Exceptions\InvalidJWTException;
use Mathrix\Lumen\JWT\Auth\JWT\JWTVerifier;
use Mathrix\Lumen\JWT\Auth\Middleware\ScopeMiddleware;

/**
 * Class JWTServiceProvider.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0use Laravel\Lumen\Application;
 *
 * @property Application $app
 */
class JWTServiceProvider extends ServiceProvider
{
    public function boot()
    {
    }


    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . "/../config/jwt_auth.php", "jwt_auth");

        $this->commands([
            JWTKeyCommand::class
        ]);

        $this->registerSingletons();

        $this->app["auth"]->viaRequest(config("jwt_auth.driver"), function (Request $request) {
            $token = $request->bearerToken();

            if ($token === null) {
                // No token was provided, skipping...
                return null;
            }

            /** @var JWTVerifier $jwtVerifier */
            $jwtVerifier = app()->make(JWTVerifier::class);
            $verified = $jwtVerifier->verify($token);

            if (!$verified) {
                throw new InvalidJWTException();
            }

            /** @var CompactSerializer $jwtSerializer */
            $jwtSerializer = app()->make(Serializer::class);
            $payload = json_decode($jwtSerializer->unserialize($token)->getPayload(), true);

            if (!isset($payload["sub"])) {
                throw new InvalidJWTException();
            }

            $sub = $payload["sub"];
            $userClass = config("jwt_auth.user_model");

            /** @var Builder $builder */
            $builder = $userClass::query();
            return $builder->where("id", "=", $sub)->first();
        });

        $this->app->routeMiddleware([
            ScopeMiddleware::$key => ScopeMiddleware::class
        ]);
    }


    /**
     * Register the singletons
     */
    public function registerSingletons()
    {
        $this->app->singleton(Algorithm::class, function () {
            $alg = config("jwt_auth.algorithm");

            if (!$alg instanceof Algorithm) {
                $alg = new $alg();
            }

            return $alg;
        });
        $this->app->singleton(AlgorithmManager::class, function () {
            return AlgorithmManager::create([$this->app->make(Algorithm::class)]);
        });
        $this->app->singleton(Serializer::class, function () {
            return new CompactSerializer(null);
        });
    }
}
