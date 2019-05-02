<?php


namespace Mathrix\Lumen\JWT\Auth;

use Carbon\Carbon;
use Exception;

/**
 * Trait HasJWTEloquent.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 *
 * @property int $id The user id.
 * @property Carbon $revoke_token_prior_to
 * @property array $scopes The user scopes.
 */
trait HasJWT
{
    /**
     * Get the subject of the JWT token; in most cases, it is the user id.
     * The value will be injected in the "sub" token claim.
     *
     * @link https://tools.ietf.org/html/rfc7519#section-4.1.2
     * @return mixed
     */
    public function getSubject()
    {
        return $this->id;
    }


    /**
     * Get the subject scopes. The method can be directly be personalized by declaring the method getScopes().
     * The value will be injected in the "scopes" token claim.
     *
     * @return mixed
     */
    public function getScopes()
    {
        return $this->scopes ?? [];
    }


    /**
     * Check if the user has the given scope.
     *
     * @param string $scope The scope
     *
     * @return bool
     */
    public function tokenCan(string $scope)
    {
        $scopes = $this->getScopes();

        if (array_search("*", $scopes) !== false) {
            return true;
        }

        return in_array($scope, $scopes);
    }
}
