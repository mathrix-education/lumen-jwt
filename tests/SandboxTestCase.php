<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests;

use Laravel\Lumen\Testing\TestCase;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SandboxTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Creates the application.
     * Needs to be implemented by subclasses.
     *
     * @return HttpKernelInterface
     */
    public function createApplication()
    {
        return require __DIR__ . '/bootstrap.php';
    }
}
