<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth;

use Illuminate\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Mathrix\Lumen\JWT\Drivers\Driver;

/**
 * Retrieve the user based on the 'sub' in a JWT token.
 */
class JWTUserResolver
{
    /**
     * @param Request $request The Illuminate HTTP request.
     *
     * @return Model|Authenticatable|null The identified user, if any.
     */
    public function __invoke(Request $request)
    {
        $bearerToken = $request->bearerToken();

        /** @var Driver $driver */
        $driver = app()->make(Driver::class);

        if (!$driver->verify($bearerToken)) {
            return null;
        }

        /** @var string $sub Get the "sub" claim. */
        $sub   = data_get('sub', $driver->unserialize($bearerToken)->getPayload());
        $model = config('jwt.user_model');

        /** @var Authenticatable $instance Only used to retrieve the auth identifier name. */
        $instance = new $model();

        /** @var Builder $builder */
        $builder = $model::query();

        return $builder->where($instance->getAuthIdentifierName(), '=', $sub)->first();
    }
}
