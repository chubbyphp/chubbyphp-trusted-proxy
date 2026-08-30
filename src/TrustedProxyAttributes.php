<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy;

/**
 * The client data the middleware sets as request attributes, the unresolved ones as null.
 */
final readonly class TrustedProxyAttributes
{
    public const string CLIENT_IP = 'clientIp';
    public const string SCHEME = 'scheme';
    public const string HOST = 'host';

    public function __construct(
        public ?string $clientIp = null,
        public ?string $scheme = null,
        public ?string $host = null,
    ) {}

    /**
     * @return array{clientIp: null|string, scheme: null|string, host: null|string}
     */
    public function toArray(): array
    {
        return [
            self::CLIENT_IP => $this->clientIp,
            self::SCHEME => $this->scheme,
            self::HOST => $this->host,
        ];
    }
}
