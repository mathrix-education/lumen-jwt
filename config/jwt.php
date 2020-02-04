<?php

declare(strict_types=1);

return [
    'auth'     => [
        'driver_name' => 'jwt',
        'user_model'  => '\\App\\User',
    ],
    'key'      => env('JWT_KEY', 'default'),
    'keys'     => [
        'default' => [
            'algorithm' => env('JWT_KEY_ALGORITHM', 'HS512'),
            'size'      => env('JWT_KEY_SIZE', 1024),
            'path'      => env('JWT_KEY_PATH', storage_path('keychain/jwt_auth.json')),
        ],
    ],
    'payload'  => env('JWT_PAYLOAD', 'default'),
    'payloads' => [
        'default' => [
            // "iss" (Issuer), see https://tools.ietf.org/html/rfc7519#section-4.1.1
            'iss' => env('JWT_PAYLOAD_ISS', 'Your Issuer'),
            // "aud" (Audience), see https://tools.ietf.org/html/rfc7519#section-4.1.3
            'aud' => env('JWT_PAYLOAD_AUD', 'Your Audience'),
            // "exp" (Expiration Time), see https://tools.ietf.org/html/rfc7519#section-4.1.4,
            'exp' => env('JWT_PAYLOAD_EXP', '+3 months'),
            // "nbf" (Not Before), see https://tools.ietf.org/html/rfc7519#section-4.1.5,
            'nbf' => env('JWT_PAYLOAD_NBF', 'now'),
            // "iat" (Issued At), see https://tools.ietf.org/html/rfc7519#section-4.1.6,
            'iat' => env('JWT_PAYLOAD_IAT', 'now'),
            // "jti" (JWT ID), see https://tools.ietf.org/html/rfc7519#section-4.1.7
            'jid' => env('JWT_PAYLOAD_JID', 'uuid'),
        ],
    ],
];
