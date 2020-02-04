<?php

declare(strict_types=1);

namespace Sandbox\Models;

class User
{
    public static $builderMock;

    public static function query()
    {
        return self::$builderMock;
    }

    public function getAuthIdentifierName() {
        return 'id';
    }
}
