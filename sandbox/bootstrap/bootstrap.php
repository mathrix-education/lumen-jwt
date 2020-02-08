<?php

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use Mathrix\Lumen\JWT\JWTServiceProvider;

// Setup directories
$base = dirname(__DIR__);
$base = realpath($base);

$app = new Laravel\Lumen\Application($base);

$app->withFacades();
$app->withEloquent();

$app->configure('app');
$app->configure('database');
$app->configure('jwt');

$app->singleton(
    Illuminate\Contracts\Console\Kernel::class,
    Laravel\Lumen\Console\Kernel::class
);

$app->singleton(
    Illuminate\Contracts\Debug\ExceptionHandler::class,
    Laravel\Lumen\Exceptions\Handler::class
);

$app->register(JWTServiceProvider::class);

return $app;
