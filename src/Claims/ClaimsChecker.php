<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Claims;

use InvalidArgumentException;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Signature\JWS;
use JsonException;
use Mathrix\Lumen\JWT\Exceptions\UnknownPayloadConfig;
use const JSON_THROW_ON_ERROR;
use function config;
use function is_array;
use function json_decode;

/**
 * Checks the claims inside a JWS token.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4.1
 * @see  ClaimCheckerManager
 */
class ClaimsChecker
{
    private array $config;
    private array $mandatoryClaims = [];

    private ClaimCheckerManager $claimChecker;

    public function __construct(array $payloadConfig)
    {
        $this->config = $payloadConfig;
    }

    /**
     * Build a payload from a configuration name.
     *
     * @param string $name The configuration name.
     *
     * @return ClaimsChecker
     *
     * @throws UnknownPayloadConfig
     */
    public static function from(string $name): ClaimsChecker
    {
        $config = config("jwt.payloads.$name");

        if ($config === null) {
            throw new UnknownPayloadConfig($name);
        }

        return new self($config);
    }

    /**
     * Check JWT claims.
     *
     * @param JWS|array $jws The JWS token or the payload as an array.
     *
     * @return array The checked claims.
     *
     * @throws JsonException if the payload cannot be decoded.
     * @throws MissingMandatoryClaimException if a mandatory claim is missing.
     * @throws InvalidClaimException at the first invalid claim.
     *
     * @noinspection PhpDocRedundantThrowsInspection
     */
    public function check($jws): array
    {
        if ($jws instanceof JWS) {
            $payload = json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR);
        } elseif (is_array($jws)) {
            $payload = $jws;
        } else {
            $message = 'Unexpected $jws argument type, expected a ' . JWS::class . ' instance or an array';
            throw new InvalidArgumentException($message);
        }

        return $this->makeClaimCheckerManager()->check($payload, $this->mandatoryClaims);
    }

    /**
     * Lazy build the claim checker.
     *
     * @return ClaimCheckerManager
     */
    private function makeClaimCheckerManager(): ClaimCheckerManager
    {
        if (isset($this->claimChecker)) {
            return $this->claimChecker;
        }

        $checkers = [];

        if (isset($this->config['iss'])) {
            // "iss" (Issuer), see https://tools.ietf.org/html/rfc7519#section-4.1.1
            $checkers[]              = new IssuerChecker([$this->config['iss']]);
            $this->mandatoryClaims[] = 'iss';
        }

        if (isset($this->config['aud'])) {
            // "aud" (Audience), see https://tools.ietf.org/html/rfc7519#section-4.1.3
            $checkers[]              = new AudienceChecker($this->config['aud']);
            $this->mandatoryClaims[] = 'aud';
        }

        if (isset($this->config['exp'])) {
            // "exp" (Expiration Time), see https://tools.ietf.org/html/rfc7519#section-4.1.4
            $checkers[]              = new ExpirationTimeChecker();
            $this->mandatoryClaims[] = 'exp';
        }

        if (isset($this->config['nbf'])) {
            // "nbf" (Not Before), see https://tools.ietf.org/html/rfc7519#section-4.1.5
            $checkers[]              = new NotBeforeChecker();
            $this->mandatoryClaims[] = 'nbf';
        }

        if (isset($this->config['iat'])) {
            // "iat" (Issued At), see https://tools.ietf.org/html/rfc7519#section-4.1.6
            $checkers[]              = new IssuedAtChecker();
            $this->mandatoryClaims[] = 'iat';
        }

        $this->claimChecker = new ClaimCheckerManager($checkers);

        return $this->claimChecker;
    }
}
