<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Auth\Tests;

use Laravel\Lumen\Testing\TestCase;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SandboxTestCase extends TestCase
{
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
