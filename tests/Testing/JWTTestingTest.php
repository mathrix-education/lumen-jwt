<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Mathrix\Lumen\JWT\Testing\JWTTesting;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mockery;

/**
 * @testdox JWTTesting utility
 * @coversDefaultClass \Mathrix\Lumen\JWT\Testing\JWTTesting
 */
class JWTTestingTest extends SandboxTestCase
{
    /**
     * @testdox impersonates a user
     * @covers ::actingAs
     */
    public function testActingAs(): void
    {
        $user = Mockery::mock(Authenticatable::class);
        JWTTesting::actingAs($user);

        $this->assertEquals($user, Auth::user());
    }
}
