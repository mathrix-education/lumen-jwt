<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Commands;

use Mathrix\Lumen\JWT\Tests\SandboxTestCase;

/**
 * @testdox Artisan Command `jwt:benchmark`
 * @coversDefaultClass \Mathrix\Lumen\JWT\Commands\JWTBenchmarkCommand
 */
class JWTBenchmarkCommandTest extends SandboxTestCase
{
    /**
     * @testdox runs the benchmark using all available algorithms
     * @covers ::handle
     */
    public function testBenchmark(): void
    {
        $this->assertEquals(0, $this->artisan('jwt:benchmark', ['--iterations' => 1]));
    }
}
