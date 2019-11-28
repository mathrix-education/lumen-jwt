<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth;

use Illuminate\Database\Eloquent\Model;
use function array_search;
use function in_array;

/**
 * @mixin Model
 */
trait HasJWT
{
    /** @var string The attribute used to forge the "sub" claim of the JWT */
    protected $jwtSubAttribute = null;
    /** @var string The attribute which represents the user scopes. */
    protected $jwtScopesAttribute = 'scopes';

    /**
     * Get the subject of the JWT token; in most cases, it is the user id.
     * The value will be injected in the "sub" token claim.
     *
     * @link https://tools.ietf.org/html/rfc7519#section-4.1.2
     *
     * @return int|string
     */
    public function getSubject()
    {
        if ($this->jwtSubAttribute !== null) {
            return $this->getAttribute($this->jwtSubAttribute);
        }

        return $this->getKey();
    }

    /**
     * Get the subject scopes. The method can be directly be personalized by declaring the method getScopes().
     * The value will be injected in the "scopes" token claim.
     *
     * @return mixed
     */
    public function getScopes(): array
    {
        return $this->getAttribute($this->jwtScopesAttribute) ?? [];
    }

    /**
     * Check if the user has the given scope.
     *
     * @param string $scope The scope
     *
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        $scopes = $this->getScopes();

        if (array_search('*', $scopes) !== false) {
            return true;
        }

        return in_array($scope, $scopes);
    }
}
