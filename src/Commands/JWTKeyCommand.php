<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Commands;

use Illuminate\Console\Command;
use Jose\Component\KeyManagement\JWKFactory;
use Mathrix\Lumen\JWT\Auth\JWT;
use const JSON_PRETTY_PRINT;
use function chmod;
use function config;
use function file_exists;
use function file_put_contents;
use function json_encode;
use function storage_path;

/**
 * Generate a new JWT key. By default, it will use the config/jwt_auth.php configuration file.
 */
class JWTKeyCommand extends Command
{
    protected $signature = 'jwt:key '
    . '{--f|force : For the key creation, even if a key already exist} '
    . '{--type=ecdsa : The key type, can only be "rsa" or "ecdsa"} '
    . '{--size=4096 : RSA only: the RSA key size} '
    . '{--curve=P-521 : ECDSA only: the elliptic curve used to generate the key} '
    . '{--path= : The key path, relative to storage directory} ';

    public function handle()
    {
        $force = $this->option('force') !== false;
        $type  = $this->option('type') ?? config('jwt_auth.key.type') ?? JWT::ECDSA_TYPE;
        $path  = $this->option('path') ?? config('jwt_auth.key.path') ?? storage_path('jwt_key.json');

        switch ($type) {
            case JWT::ECDSA_TYPE:
                $curve = $this->option('curve') ?? config('jwt_auth.key.ecdsa.curve') ?? JWT::CURVE_P521;
                $key   = JWKFactory::createECKey($curve);
                break;
            case JWT::RSA_TYPE:
            default:
                $size = (int)$this->option('size') ?? (int)config('jwt_auth.key.rsa.size') ?? 4096;
                $key  = JWKFactory::createRSAKey($size);
                break;
        }

        // Write the key
        if (file_exists($path) && !$force) {
            $this->line("A key already exists at $path, ignoring");
        } else {
            file_put_contents($path, json_encode($key->jsonSerialize(), JSON_PRETTY_PRINT));
            chmod($path, 0600); // Secure the key
            $this->line("Generated a new key in {$path}");
        }
    }
}
