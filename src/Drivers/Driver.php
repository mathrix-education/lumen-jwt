<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Drivers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Validator;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Mathrix\Lumen\JWT\Claims\ClaimsChecker;
use Mathrix\Lumen\JWT\Claims\ClaimsGenerator;
use Mathrix\Lumen\JWT\Exceptions\InvalidAlgorithm;
use Mathrix\Lumen\JWT\Exceptions\InvalidConfiguration;
use Mathrix\Lumen\JWT\Exceptions\IO;
use Mathrix\Lumen\JWT\Exceptions\MissingLibrary;
use const JSON_PRETTY_PRINT;
use function array_merge;
use function chmod;
use function class_basename;
use function class_exists;
use function dirname;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function implode;
use function in_array;
use function is_readable;
use function is_string;
use function is_writable;
use function json_encode;

/**
 * Base class for the JWT providers.
 */
abstract class Driver
{
    public const ALGORITHM_NAMESPACE = 'Jose\\Component\\Signature\\Algorithm';
    public const KEY_PERMS           = 0600;

    /** @var string|null The key location on the disk */
    protected $path;
    /** @var string The algorithm class */
    protected $algorithm;
    /** @var JWK $jwk The JSON Web Key */
    protected $jwk;

    /** @var JWSBuilder The JSON Web Signature builder */
    private $builder;
    /** @var ClaimsGenerator $claimsGenerator The claims generator */
    private $claimsGenerator;
    /** @var JWSVerifier The JSON Web Signature verifier */
    private $verifier;
    /** @var CompactSerializer The serializer. */
    protected $serializer;

    /** @var HeaderCheckerManager $headerChecker The header checker */
    private $headerChecker;
    /** @var ClaimsChecker $claimChecker The claim checker */
    private $claimChecker;

    /**
     * @param array $keyConfig
     * @param array $claimsConfig
     */
    public function __construct(array $keyConfig, array $claimsConfig = [])
    {
        $this->apply($keyConfig);

        /** @var Algorithm $algorithmInstance */
        $algorithmInstance = new $this->algorithm();

        $manager               = new AlgorithmManager([$algorithmInstance]);
        $this->builder         = new JWSBuilder($manager);
        $this->claimsGenerator = new ClaimsGenerator($claimsConfig);
        $this->verifier        = new JWSVerifier($manager);
        $this->serializer      = new CompactSerializer();

        // Create checkers
        $this->headerChecker = new HeaderCheckerManager([
            new AlgorithmChecker([$algorithmInstance->name()]),
        ], [new JWSTokenSupport()]);

        $this->claimChecker = new ClaimsChecker($claimsConfig);
    }

    /**
     * Get a driver instance from a key and payload configuration.
     *
     * @param array $keyConfig
     * @param array $claimsConfig
     *
     * @return Driver
     */
    public static function from(array $keyConfig, array $claimsConfig = []): Driver
    {
        if (!isset($keyConfig['algorithm'])) {
            throw new InvalidConfiguration('Algorithm is required');
        }

        if (isset($keyConfig['algorithm']) && !class_exists($keyConfig['algorithm'])) {
            // Prepend algorithm namespace if necessary
            $keyConfig['algorithm'] = self::ALGORITHM_NAMESPACE . "\\{$keyConfig['algorithm']}";
        }

        if (in_array($keyConfig['algorithm'], ECDSADriver::ALGORITHMS, true)) {
            return new ECDSADriver($keyConfig, $claimsConfig);
        }

        if (in_array($keyConfig['algorithm'], EdDSADriver::ALGORITHMS, true)) {
            return new EdDSADriver($keyConfig, $claimsConfig);
        }

        if (in_array($keyConfig['algorithm'], HMACDriver::ALGORITHMS, true)) {
            return new HMACDriver($keyConfig, $claimsConfig);
        }

        if (in_array($keyConfig['algorithm'], RSADriver::ALGORITHMS, true)) {
            return new RSADriver($keyConfig, $claimsConfig);
        }

        throw new InvalidAlgorithm($keyConfig['algorithm']);
    }

    /**
     * Get the supported algorithms, using the passed key config.
     *
     * @param array $keyConfig
     *
     * @return array
     */
    abstract protected function getSupportedAlgorithms(array $keyConfig): array;

    /**
     * Get the additional validation rules, using the passed key config.
     *
     * @param array $keyConfig
     *
     * @return array
     */
    abstract protected function getValidationRules(array $keyConfig): array;

    /**
     * Apply and validate the given configuration.
     *
     * @param array $keyConfig The key configuration.
     */
    protected function apply(array $keyConfig): void
    {
        if (isset($keyConfig['algorithm']) && !class_exists($keyConfig['algorithm'])) {
            // Prepend algorithm namespace if necessary
            $keyConfig['algorithm'] = self::ALGORITHM_NAMESPACE . "\\{$keyConfig['algorithm']}";
        }

        // Build validation rules
        $rules = array_merge([
            'algorithm' => 'required|in:' . implode(',', $this->getSupportedAlgorithms($keyConfig)),
        ], $this->getValidationRules($keyConfig));

        $validator = Validator::make($keyConfig, $rules);

        if ($validator->fails()) {
            throw InvalidConfiguration::validation($validator);
        }

        // Set algorithm
        $this->setAlgorithm($keyConfig['algorithm']);

        if (isset($keyConfig['path'])) {
            $this->setPath($keyConfig['path']);
        }

        $this->postApply($keyConfig);
    }

    /**
     * Do additional actions after config application. The provided configuration can now be considered as valid.
     *
     * @param array $keyConfig The key configuration.
     */
    protected function postApply(array $keyConfig): void
    {
    }

    /**
     * Get the chosen algorithm class.
     *
     * @return string
     */
    final public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Get the chosen algorithm name.
     *
     * @see Algorithm::name()
     *
     * @return string
     */
    final public function getAlgorithmName(): string
    {
        /** @var Algorithm $instance */
        $instance = new $this->algorithm();

        return $instance->name();
    }

    /**
     * Set the algorithm of the driver and do some checks.
     *
     * @param string $algorithm The algorithm.
     *
     * @return Driver
     */
    private function setAlgorithm(string $algorithm): Driver
    {
        if (class_exists($algorithm)) {
            // $algorithm is already the FQ class name.
            $this->algorithm = $algorithm;

            return $this;
        }

        // We already know at this point that an exception will be thrown
        // Try to determine if the algorithm does not exists due to a missing library
        if (in_array($algorithm, ECDSADriver::ALGORITHMS, true)) {
            $missing = ECDSADriver::LIBRARY;
        } elseif (in_array($algorithm, EdDSADriver::ALGORITHMS, true)) {
            $missing = EdDSADriver::LIBRARY;
        } elseif (in_array($algorithm, HMACDriver::ALGORITHMS, true)) {
            $missing = HMACDriver::LIBRARY;
        } elseif (in_array($algorithm, RSADriver::ALGORITHMS, true)) {
            $missing = RSADriver::LIBRARY;
        }

        if (isset($missing)) {
            throw new MissingLibrary($missing, $algorithm);
        }

        // The algorithm could not be found in our drivers, throw a generic InvalidAlgorithm
        throw new InvalidAlgorithm($algorithm);
    }

    /**
     * Get the key path.
     *
     * @return string|null
     */
    public function getPath(): ?string
    {
        return $this->path;
    }

    /**
     * Set the key path.
     *
     * @param string $path The key path.
     *
     * @return Driver
     */
    private function setPath(string $path): Driver
    {
        $dir = dirname($path);

        if (!file_exists($path) && !file_exists($dir)) {
            throw new IO("Directory $dir does not exist and thus the key cannot be created at $path");
        }

        if (file_exists($path) && !is_readable($path)) {
            throw new IO("Key exists at $path but is readable");
        }

        if (!file_exists($path) && file_exists($dir) && !is_writable($dir)) {
            throw new IO("Directory $dir exists but is not writable and thus the key cannot be created at $path");
        }

        $this->path = $path;

        return $this;
    }

    /**
     * Generate a JWK using the configuration parameters.
     *
     * @return JWK
     */
    abstract protected function generate(): JWK;

    /**
     * Instantiate the JWK from the existing key file.
     *
     * @return JWK
     */
    private function readKey(): JWK
    {
        return JWK::createFromJson(file_get_contents($this->path));
    }

    /**
     * Write the current loaded JWK into the path.
     *
     * @param JWK $jwk
     *
     * @return Driver
     */
    private function writeKey(JWK $jwk): Driver
    {
        $keyString = json_encode($jwk->jsonSerialize(), JSON_PRETTY_PRINT, 512);
        file_put_contents($this->path, $keyString);
        chmod($this->path, self::KEY_PERMS);

        return $this;
    }

    /**
     * Lazily get the driver key.
     *
     * @return JWK
     */
    private function getKey(): JWK
    {
        if (isset($this->jwk)) {
            return $this->jwk;
        }

        if ($this->getPath() === null) {
            // In-memory key, generate a new key
            $jwk = $this->generate();
        } elseif (file_exists($this->path)) {
            // Read the key from the $path
            $jwk = $this->readKey();
        } else {
            //Key does not exist, generate and write a new key
            $jwk = $this->generate();
            $this->writeKey($jwk);
        }

        $this->jwk = $jwk;

        return $jwk;
    }

    /**
     * Get the public JWK.
     *
     * @return JWK
     */
    final public function getPublicJWK(): JWK
    {
        return $this->getKey()->toPublic();
    }

    /**
     * Add the configured claims to the payload and sign it using the driver key.
     * If the payload is an instance of `Authenticatable`, add the 'sub' claim from the getAuthIdentifier method.
     * If you want to add more private claims, you have to pass the sub claim explicitly.
     *
     * @see Authenticatable::getAuthIdentifier()
     *
     * @param bool                  $serialize Serialize the signed JWS.
     * @param Authenticatable|array $payload   The user/payload to sign.
     *
     * @return string|JWS
     */
    final public function sign($payload, bool $serialize = true)
    {
        if ($payload instanceof Authenticatable) {
            $payload = ['sub' => (string)$payload->getAuthIdentifier()];
        }

        $payload       = array_merge($payload, $this->claimsGenerator->generate());
        $payloadString = json_encode($payload, 0, 512);

        $jws = $this->builder->create()
            ->withPayload($payloadString)
            ->addSignature($this->getKey(), [
                'typ' => 'JWT',
                'alg' => class_basename($this->algorithm),
            ])
            ->build();

        return !$serialize ? $jws : $this->serializer->serialize($jws);
    }

    /**
     * Serialize a JWS using the Compact Serialize.
     *
     * @see CompactSerializer
     *
     * @param JWS $jws the JSON Web Token to serialize.
     *
     * @return string
     */
    public function serialize(JWS $jws): string
    {
        return $this->serializer->serialize($jws);
    }

    /**
     * Verify a JWS claims.
     *
     * @param string|JWS $jws The JWS (plain JWS or string).
     *
     * @return bool
     *
     * @throws InvalidClaimException
     * @throws MissingMandatoryClaimException
     */
    final public function check($jws): bool
    {
        if (is_string($jws)) {
            $jws = $this->unserialize($jws);
        }

        $this->headerChecker->check($jws, 0);
        $this->claimChecker->check($jws);

        return true;
    }

    /**
     * Unserialize a JWS.
     *
     * @param string $bearerToken The JWS (plain JWS or string).
     *
     * @return JWS
     */
    final public function unserialize(string $bearerToken): JWS
    {
        return $this->serializer->unserialize($bearerToken);
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
        if (is_string($jws)) {
            $jws = $this->unserialize($jws);
        }

        return $this->verifier->verifyWithKey($jws, $this->getKey(), 0);
    }
}
