<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Wrappers;

use Mathrix\Lumen\JWT\Exceptions\UnknownPayloadConfig;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Claims\ClaimChecker;

/**
 * @testdox Payload Configuration
 * @coversDefaultClass \Mathrix\Lumen\JWT\Claims\ClaimChecker
 */
class PayloadConfigTest extends SandboxTestCase
{
    /**
     * @testdox returns a instance of PayloadConfig when the config exists
     * @covers ::from
     */
    public function testFromExisting(): void
    {
        $config = ClaimChecker::from('default');

        $this->assertNotNull($config);
    }

    /**
     * @testdox throws an UnknownPayloadConfig exception when the config does not exists
     * @covers ::from
     */
    public function testFromNonExisting(): void
    {
        $this->expectException(UnknownPayloadConfig::class);
        ClaimChecker::from('default-non-existing');
    }
}
