<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use InvalidArgumentException;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\Serializer;
use Laravel\Lumen\Application;
use Mathrix\Lumen\JWT\Auth\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Auth\Exceptions\InvalidJWT;
use Mathrix\Lumen\JWT\Auth\JWT\JWTIssuer;
use Mathrix\Lumen\JWT\Auth\JWT\JWTVerifier;
use Mathrix\Lumen\JWT\Auth\Middleware\LoggedMiddleware;
use Mathrix\Lumen\JWT\Auth\Middleware\ScopeMiddleware;
use function app;
use function config;
use function json_decode;

/**
 * @property Application $app
 */
class JWTAuthServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/jwt_auth.php', 'jwt_auth');

        $this->commands([JWTKeyCommand::class]);

        $this->registerSingletons();

        $this->app['auth']->viaRequest(config('jwt_auth.driver'), static function (Request $request) {
            $token = $request->bearerToken();

            if ($token === null) {
                // No token was provided, skipping...
                return null;
            }

            /** @var JWTVerifier $jwtVerifier */
            $jwtVerifier = app()->make(JWTVerifier::class);

            $verified = false;

            try {
                $verified = $jwtVerifier->verify($token);
            } catch (InvalidArgumentException $e) {
                // Do nothing, token is already invalid
            }

            if (!$verified) {
                throw new InvalidJWT();
            }

            /** @var CompactSerializer $jwtSerializer */
            $jwtSerializer = app()->make(Serializer::class);
            $payload       = json_decode($jwtSerializer->unserialize($token)->getPayload(), true);

            if (!isset($payload['sub'])) {
                throw new InvalidJWT();
            }

            $sub       = $payload['sub'];
            $userClass = config('jwt_auth.user_model');

            /** @var Builder $builder */
            $builder = $userClass::query();

            return $builder->where('id', '=', $sub)->first();
        });

        $this->app->routeMiddleware([
            LoggedMiddleware::$key => LoggedMiddleware::class,
            ScopeMiddleware::$key  => ScopeMiddleware::class,
        ]);
    }

    /**
     * Register the singletons
     */
    public function registerSingletons()
    {
        $this->app->singleton(Algorithm::class, static function () {
            $alg = config('jwt_auth.algorithm');

            if (!$alg instanceof Algorithm) {
                $alg = new $alg();
            }

            return $alg;
        });
        $this->app->singleton(AlgorithmManager::class, function () {
            return new AlgorithmManager([$this->app->make(Algorithm::class)]);
        });
        $this->app->singleton(Serializer::class, static function () {
            return new CompactSerializer();
        });
        $this->app->singleton(JWTIssuer::class, static function () {
            return new JWTIssuer();
        });
        $this->app->singleton(JWTVerifier::class, static function () {
            return new JWTVerifier();
        });
    }
}
