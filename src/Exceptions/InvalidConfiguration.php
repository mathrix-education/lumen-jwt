<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Exceptions;

use Illuminate\Contracts\Validation\Validator;
use InvalidArgumentException;
use Throwable;
use function implode;

class InvalidConfiguration extends InvalidArgumentException
{
    public static function validation(Validator $validator, ?Throwable $previous = null): InvalidConfiguration
    {
        $messages = implode("\n", $validator->getMessageBag()->all());
        $message  = "Configuration validation failed\n$messages";

        return new self($message, 0, $previous);
    }

    public static function claim(string $claim, ?Throwable $previous = null): InvalidConfiguration
    {
        $message = "Invalid claim {$claim} configuration";

        if ($previous !== null) {
            $message .= ": {$previous->getMessage()}";
        }

        return new self($message, 0, $previous);
    }
}
