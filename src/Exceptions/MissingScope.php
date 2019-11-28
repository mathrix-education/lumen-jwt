<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Exceptions;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Throwable;

class MissingScope extends AccessDeniedHttpException
{
    /** @var string The required scope */
    private $scope;

    public function __construct(string $scope, ?Throwable $previous = null, int $code = 0, array $headers = [])
    {
        parent::__construct("Missing scope: $scope", $previous, $code, $headers);
        $this->scope = $scope;
    }

    /**
     * Get the required scope.
     *
     * @return string
     */
    public function getScope(): string
    {
        return $this->scope;
    }
}
