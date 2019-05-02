<?php

use Jose\Component\Signature\Algorithm\ES512;

return [
    "key" => [
        "path" => storage_path("keychain/jwt_auth.json"),
        "type" => "ecdsa",
        "curve" => "P-521", // ECDSA only
        "size" => 4096, // RSA only
    ],
    "algorithm" => ES512::class,
    "user_model" => "\\App\\Models\\User",
    "driver" => "jwt-auth",
    "guard" => "api",
    "jwt" => [
        "iss" => "Mathrix Education API",
        "aud" => "Mathrix Education API",
    ]
];
