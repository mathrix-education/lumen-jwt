<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Commands;

use Illuminate\Console\Command;

/**
 *
 */
class JWTBenchmarkCommand extends Command
{
    private const PAYLOAD = ['hello' => 'world'];
    protected $signature = 'jwt:benchmark';

    public function handle(): void
    {

    }

    private function benchmarkECDSA()
    {
    }
}
