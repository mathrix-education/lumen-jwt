<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT;

use Illuminate\Auth\AuthManager;
use Illuminate\Support\ServiceProvider;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Signature\JWSTokenSupport;
use Laravel\Lumen\Application;
use Mathrix\Lumen\JWT\Auth\JWTUserResolver;
use Mathrix\Lumen\JWT\Commands\JWTKeyCommand;
use Mathrix\Lumen\JWT\Config\JWTConfig;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Utils\JWTUtils;
use function config;

/**
 * @property Application $app
 */
class JWTServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/jwt.php', 'jwt');

        $this->commands([JWTKeyCommand::class]);

        $this->app->singleton(Driver::class, static function () {
            return Driver::from(JWTConfig::key());
        });

        /** @var AuthManager $auth */
        $auth = app()->make('auth');
        $auth->viaRequest(config('jwt.driver'), new JWTUserResolver());
    }
}
