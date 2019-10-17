<?php

declare(strict_types=1);

use Mathrix\Lumen\JWT\Auth\JWTAuthServiceProvider;

// Setup directories
$base = __DIR__ . '/../sandbox';
mkdirp($base);
$base = realpath($base);
mkdirp("$base/database");
mkdirp("$base/storage");
mkdirp("$base/storage/keychain");
mkdirp("$base/storage/logs");

$app = new Laravel\Lumen\Application($base);

$app->withFacades();
$app->withEloquent();

$app->singleton(
    Illuminate\Contracts\Console\Kernel::class,
    Laravel\Lumen\Console\Kernel::class
);

$app->singleton(
    Illuminate\Contracts\Debug\ExceptionHandler::class,
    Laravel\Lumen\Exceptions\Handler::class
);

$app->register(JWTAuthServiceProvider::class);

return $app;
