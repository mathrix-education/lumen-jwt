<?php

declare(strict_types=1);

namespace Mathrix\Lumen\JWT\Claims;

use DateTime;
use Exception;
use Mathrix\Lumen\JWT\Exceptions\InvalidConfiguration;
use Ramsey\Uuid\Uuid;

class ClaimsGenerator
{
    private array $config;

    public function __construct($config)
    {
        $this->config = $config;
    }

    /**
     * Generate claims based on the passed configuration.
     *
     * @throws InvalidConfiguration
     */
    public function generate(): array
    {
        $claims = [];

        if (isset($this->config['iss'])) {
            $claims['iss'] = $this->config['iss'];
        }

        if (isset($this->config['aud'])) {
            $claims['aud'] = $this->config['aud'];
        }

        if (isset($this->config['exp'])) {
            try {
                $claims['exp'] = (new DateTime($this->config['exp']))->getTimestamp();
            } catch (Exception $e) {
                throw InvalidConfiguration::claim('exp', $e);
            }
        }

        if (isset($this->config['nbf'])) {
            try {
                $claims['nbf'] = (new DateTime($this->config['nbf']))->getTimestamp();
            } catch (Exception $e) {
                throw InvalidConfiguration::claim('nbf', $e);
            }
        }

        if (isset($this->config['iat'])) {
            try {
                $claims['iat'] = (new DateTime($this->config['iat']))->getTimestamp();
            } catch (Exception $e) {
                throw InvalidConfiguration::claim('iat', $e);
            }
        }

        if (isset($this->config['jid'])) {
            try {
                $claims['jid'] = Uuid::uuid4();
            } catch (Exception $e) {
                throw InvalidConfiguration::claim('exp', $e);
            }
        }

        return $claims;
    }
}
