<?php

declare(strict_types=1);

return [
    'defaults' => ['guard' => 'jwt'],
    'guards'   => [
        'jwt' => ['driver' => 'jwt'],
    ],
];
