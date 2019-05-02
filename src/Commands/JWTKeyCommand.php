<?php

namespace Mathrix\Lumen\JWT\Auth\Commands;

use Illuminate\Console\Command;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Class JWTKeyCommand.
 *
 * @author Mathieu Bour <mathieu@mathrix.fr>
 * @copyright Mathrix Education SA.
 * @since 1.0.0
 */
class JWTKeyCommand extends Command
{
    protected $signature = "jwt:key {--keyPath= : The key path, relative to storage}";


    public function handle()
    {
        switch (config("jwt_auth.key.type")) {
            case "rsa":
                $key = JWKFactory::createRSAKey(config("jwt_auth.key.size"));
                break;
            case "ecdsa":
            default:
                $key = JWKFactory::createECKey(config("jwt_auth.key.curve"));
                break;
        }

        $keyPath = config("jwt_auth.key.path");
        $dirname = dirname($keyPath);

        if (!is_dir($dirname)) {
            mkdir($dirname, 0600, true);
        }

        file_put_contents(
            $keyPath,
            json_encode($key->jsonSerialize(), JSON_PRETTY_PRINT)
        );
        chmod($keyPath, 0600); // Secure the key

        $this->line("Generated a new key in {$keyPath}");
    }
}
