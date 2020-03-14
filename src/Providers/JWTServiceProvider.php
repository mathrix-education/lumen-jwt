<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT;

use Illuminate\Auth\AuthManager;
use Illuminate\Support\ServiceProvider;
use Laravel\Lumen\Application;
use Mathrix\Lumen\JWT\Auth\JWTUserResolver;
use Mathrix\Lumen\JWT\Commands\JWTBenchmarkCommand;
use Mathrix\Lumen\JWT\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Utils\JWTConfig;
use function app;

/**
 * @property Application $app
 */
class JWTServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/jwt.php', 'jwt');

        $this->commands([JWTKeyCommand::class, JWTBenchmarkCommand::class]);

        $this->app->singleton(Driver::class, static function () {
            return Driver::from(JWTConfig::key(), JWTConfig::payload());
        });

        /** @var AuthManager $auth */
        $auth = $this->app['auth'];
        $auth->viaRequest($this->app['config']->get('jwt.auth.driver_name', 'jwt'), new JWTUserResolver());
    }
}
