<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Wrappers;

use Illuminate\Contracts\Container\BindingResolutionException;
use Mathrix\Lumen\JWT\Claims\ClaimsChecker;
use Mathrix\Lumen\JWT\Exceptions\UnknownPayloadConfig;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;

/**
 * @testdox Payload Configuration
 * @coversDefaultClass \Mathrix\Lumen\JWT\Claims\ClaimsChecker
 */
class PayloadConfigTest extends SandboxTestCase
{
    /**
     * @testdox returns a instance of PayloadConfig when the config exists
     * @covers ::from
     */
    public function testFromExisting(): void
    {
        $config = ClaimsChecker::from('default');

        $this->assertNotNull($config);
    }

    /**
     * @throws BindingResolutionException
     *
     * @testdox throws an UnknownPayloadConfig exception when the config does not exists
     * @covers ::from
     */
    public function testFromNonExisting(): void
    {
        $this->expectException(UnknownPayloadConfig::class);
        ClaimsChecker::from('default-non-existing');
    }
}
