<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Tests\Claims;

use Illuminate\Contracts\Container\BindingResolutionException;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Mathrix\Lumen\JWT\Claims\ClaimsChecker;
use Mathrix\Lumen\JWT\Drivers\Driver;
use Mathrix\Lumen\JWT\Tests\SandboxTestCase;
use Mathrix\Lumen\JWT\Utils\JWTConfig;
use function app;
use function collect;

/**
 * @testdox Claims Checker
 * @coversDefaultClass \Mathrix\Lumen\JWT\Claims\ClaimsChecker
 */
class ClaimsCheckerTest extends SandboxTestCase
{
    public function claims(): array
    {
        return collect(['iss', 'aud', 'exp', 'nbf', 'iat'])
            ->mapWithKeys(static function ($claim) {
                return [$claim => [$claim]];
            })
            ->toArray();
    }

    /**
     * @param string $claim
     *
     * @throws BindingResolutionException
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     *
     * @testdox      checks JWS using claim $claim
     * @covers ::check
     * @covers ::makeClaimCheckerManager
     * @dataProvider claims
     */
    public function testCheckClaim(string $claim): void
    {
        /** @var Driver $driver */
        $driver = app()->make(Driver::class);
        $jws    = $driver->sign(['sub' => 1], false);

        $checker = new ClaimsChecker([$claim => JWTConfig::payload(null, $claim)]);

        $this->assertNotNull($checker->check($jws));
    }
}
