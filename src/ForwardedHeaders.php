<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy;

/**
 * The (case insensitive) names of the headers the proxies forward the client data within, `for` is the base for the
 * trust decision, the others get only resolved when a client ip was resolved (null disables them).
 */
final readonly class ForwardedHeaders
{
    public const string DEFAULT_FOR = 'X-Forwarded-For';
    public const string DEFAULT_PROTO = 'X-Forwarded-Proto';
    public const string DEFAULT_HOST = 'X-Forwarded-Host';

    // RFC 9110 token
    private const string TOKEN_PATTERN = '/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+\z/';

    /**
     * @param string      $for   the client ip, e.g. `X-Forwarded-For` or `X-Real-IP`
     * @param null|string $proto the scheme the client used, e.g. `X-Forwarded-Proto`
     * @param null|string $host  the host the client requested, e.g. `X-Forwarded-Host`
     */
    public function __construct(
        public string $for = self::DEFAULT_FOR,
        public ?string $proto = self::DEFAULT_PROTO,
        public ?string $host = self::DEFAULT_HOST,
    ) {
        foreach (['for' => $for, 'proto' => $proto, 'host' => $host] as $key => $name) {
            if (null !== $name && 1 !== preg_match(self::TOKEN_PATTERN, $name)) {
                throw new \InvalidArgumentException(
                    \sprintf('headers.%s must be a valid header name, "%s" given', $key, $name)
                );
            }
        }
    }
}
