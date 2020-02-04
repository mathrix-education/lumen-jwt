<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Mathrix\Lumen\JWT\Config\JWTConfig;
use Mathrix\Lumen\JWT\Config\JWTConfigValidator;
use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use function chmod;
use function class_basename;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function is_array;
use function json_decode;
use function json_encode;

/**
 * Base class for the JWT providers.
 */
abstract class Driver
{
    public const  ALGORITHMS = [];
    public const  KEY_PERMS  = 0600;

    /** @var string The key location on the disk */
    protected string $path;
    /** @var JWTConfigValidator */
    protected JWTConfigValidator $validator;

    /** @var JWK $jwk The JSON Web Key */
    protected JWK $jwk;
    /** @var string The algorithm class */
    protected string $algorithm;
    /** @var JWSBuilder The JSON Web Signature builder */
    private JWSBuilder $builder;
    /** @var JWSVerifier The JSON Web Signature verifier */
    private JWSVerifier $verifier;
    /** @var CompactSerializer The serializer. */
    protected CompactSerializer $serializer;

    /** @var HeaderCheckerManager $headerChecker The header checker */
    private HeaderCheckerManager $headerChecker;
    /** @var ClaimCheckerManager $claimChecker The claim checker */
    private ClaimCheckerManager  $claimChecker;

    /**
     * @param array $config The driver configuration.
     */
    public function __construct(array $config)
    {
        $this->validator = new JWTConfigValidator();
        $this->path      = $config['path'];

        $class           = static::class;
        $this->algorithm = $this->validator->algorithm($config['algorithm'], $class::ALGORITHMS);
        /** @var Algorithm $algorithm */
        $algorithm = new $this->algorithm();

        $manager          = new AlgorithmManager([$algorithm]);
        $this->builder    = new JWSBuilder($manager);
        $this->verifier   = new JWSVerifier($manager);
        $this->serializer = new CompactSerializer();

        // Load the JWK or write it if necessary
        if (file_exists($this->path)) {
            $this->validator->assertKeyReadable($this->path);
            $this->load();
        } else {
            $this->validator->assertKeyWritable($this->path);
            $this->write();
        }

        // Create checkers
        $this->headerChecker = new HeaderCheckerManager([
            new AlgorithmChecker([$algorithm->name()]),
        ], [new JWSTokenSupport()]);

        $this->claimChecker = new ClaimCheckerManager([
            new IssuerChecker([JWTConfig::payload('iss')]),
            new AudienceChecker(JWTConfig::payload('aud')),
            new ExpirationTimeChecker(),
            new NotBeforeChecker(),
            new IssuedAtChecker(),
        ]);
    }

    /**
     * Generate a JWK using the configuration parameters.
     *
     * @return JWK
     */
    abstract protected function generate(): JWK;

    /**
     * Instantiate the JWK from the existing key file.
     */
    private function load(): void
    {
        $this->jwk = JWK::createFromJson(file_get_contents($this->path));
    }

    /**
     * Write the current loaded JWK into the path.
     */
    private function write(): void
    {
        if (!isset($this->jwk)) {
            $this->jwk = $this->generate();
        }

        $keyString = json_encode($this->jwk->jsonSerialize(), JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR, 512);
        file_put_contents($this->path, $keyString);
        chmod($this->path, self::KEY_PERMS);
    }

    /**
     * Get the public JWK.
     *
     * @return JWK
     */
    final public function getPublicJWK(): JWK
    {
        return $this->jwk->toPublic();
    }

    /**
     * Sign a payload.
     *
     * @param array|string $payload
     *
     * @return JWS
     */
    final public function sign($payload): JWS
    {
        if (is_array($payload)) {
            $payload = json_encode($payload, JSON_THROW_ON_ERROR, 512);
        }

        return $this->builder->create()
            ->withPayload($payload)
            ->addSignature($this->jwk, [
                'typ' => 'JWT',
                'alg' => class_basename($this->algorithm),
            ])
            ->build();
    }

    /**
     * Sign and serialize a payload.
     *
     * @param array|string $payload
     *
     * @return string
     */
    final public function signAndSerialize($payload): string
    {
        return $this->serializer->serialize($this->sign($payload));
    }

    /**
     * Unserialize a JWS.
     *
     * @param string|JWS $jws The plain-text JWS.
     *
     * @return JWS
     */
    final public function unserialize($jws): JWS
    {
        if ($jws instanceof JWS) {
            return $jws;
        }

        return $this->serializer->unserialize($jws);
    }

    /**
     * Verify a JWS claims.
     *
     * @param string|JWS|null $jws The JWS (plain JWS or string).
     *
     * @return bool
     */
    final public function check($jws): bool
    {
        $jws = $this->unserialize($jws);

        $this->headerChecker->check($jws, 0);
        $this->claimChecker->check(json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR));

        return true;
    }

    /**
     * Verify a JWS signature.
     *
     * @param string|JWS $jws The JWS (plain JWS or string).
     *
     * @return bool If the JWS is valid.
     */
    final public function verify($jws): bool
    {
        $jws = $this->unserialize($jws);

        return $this->verifier->verifyWithKey($jws, $this->jwk, 0);
    }
}
