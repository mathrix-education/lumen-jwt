<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\ES512;

return [
    'key'        => [
        'path'  => storage_path('keychain/jwt_auth.json'),
        'type'  => 'ecdsa',
        'ecdsa' => ['curve' => 'P-521'],
        'rsa'   => ['size' => 4096],
    ],
    'algorithm'  => ES512::class,
    'user_model' => '\\App\\Models\\User',
    'expiration' => [
        'value' => 3,
        'unit'  => 'month',
    ],
    'driver'     => 'jwt-auth',
    'guard'      => 'api',
    'jwt'        => [
        'iss' => 'Unknown Issuer',
        'aud' => 'Unknown Audience',
    ],
];
