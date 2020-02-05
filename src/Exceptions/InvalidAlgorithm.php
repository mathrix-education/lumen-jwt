<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Exceptions;

use RuntimeException;
use Throwable;

/**
 * Thrown when the algorithm could not be found and is not in the standard web-token libraries.
 */
class InvalidAlgorithm extends RuntimeException
{
    public function __construct(string $algorithm, ?Throwable $previous = null)
    {
        parent::__construct("Invalid algorithm $algorithm", 0, $previous);
    }
}
