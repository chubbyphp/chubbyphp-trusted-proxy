<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Resolves the client ip, scheme and host of a request out of the forwarded headers:
 *  - the address of the connection (the `remoteAddress` attribute, or the `REMOTE_ADDR` server param, as set by the
 *    server, a port gets stripped) anchors the trust: a connection from outside the trusted ranges is the client
 *    itself, its address is the client ip and the headers get ignored. Without any address, nothing gets resolved
 *    (fail closed), unless the resolver got created with `requireRemoteAddress: false`, in which case the last hop
 *    counts as trusted (the server must then not be reachable except through the proxies).
 *  - the entries of the `for` header get walked from the right (the entries as appended by the proxies, the nearest
 *    one last), skipping the ones within the trusted proxies ips / cidrs (e.g. `['10.0.0.0/8', '::1']`, ipv4 mapped
 *    ipv6 addresses match ipv4 subnets), the first untrusted one is the client ip, if it is a valid ip. Only trusted
 *    entries, or an untrusted one which is not a valid ip (blank, `unknown`, `ip:port`, junk), resolve nothing.
 *  - the client ip gets canonicalized (`::ffff:203.0.113.1` as `203.0.113.1`, `0:0::1` as `::1`), so that the same
 *    client always resolves to the same string.
 *  - the scheme and host get only resolved when a client ip was resolved: the entry at the same position, if the
 *    header has as many entries as the `for` header (proxies appending to all of them), the last (the one the nearest
 *    proxy set) otherwise. The scheme gets lowercased and must be `http` or `https`, the host must be a syntactically
 *    valid host (with an optional port from 1 to 65535), everything else resolves null.
 */
final class ForwardedResolver implements ForwardedResolverInterface
{
    public const string REMOTE_ADDRESS_ATTRIBUTE = 'remoteAddress';
    public const string REMOTE_ADDR_SERVER_PARAM = 'REMOTE_ADDR';

    private const array SCHEMES = ['http', 'https'];

    // hostname or ipv4 (labels of letters, digits, hyphens), or a bracketed ipv6, each with an optional port, the
    // bracketed ipv6 and the port get validated afterwards
    private const string HOST_PATTERN = '/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.?|\[(?<ipv6>[0-9A-Fa-f:.]+)\])(?::(?<port>\d{1,5}))?\z/';

    private const int MIN_PORT = 1;
    private const int MAX_PORT = 65535;

    /**
     * @var list<array{0: string, 1: string}> the packed (masked) network address and the packed mask
     */
    private readonly array $subnets;

    private readonly ForwardedHeaders $headers;

    /**
     * @param list<string> $trustedProxies       the ips / cidrs of the proxies
     * @param bool         $requireRemoteAddress resolve nothing if the request carries no address of the connection
     */
    public function __construct(
        array $trustedProxies,
        ?ForwardedHeaders $headers = null,
        private readonly bool $requireRemoteAddress = true,
    ) {
        // an empty list trusts no entry, so the last one (set by the nearest proxy) would resolve as the client ip:
        // reject it, as the resolver makes no sense without a trusted proxy
        if ([] === $trustedProxies) {
            throw new \InvalidArgumentException('trustedProxies must not be empty');
        }

        $this->subnets = array_map(static fn (mixed $subnet): array => self::parseSubnet($subnet), $trustedProxies);
        $this->headers = $headers ?? new ForwardedHeaders();
    }

    public function resolve(ServerRequestInterface $request): TrustedProxyAttributes
    {
        $remoteAddress = $this->remoteAddress($request);

        // the client connected directly: its address is the client ip, the headers get ignored
        if (null !== $remoteAddress && !$this->isTrustedProxy($remoteAddress)) {
            return new TrustedProxyAttributes(self::asIp($remoteAddress));
        }

        if (null === $remoteAddress && $this->requireRemoteAddress) {
            return new TrustedProxyAttributes();
        }

        return $this->resolveHeaders($request);
    }

    /**
     * Resolves out of the forwarded headers, for a request through a trusted proxy.
     */
    private function resolveHeaders(ServerRequestInterface $request): TrustedProxyAttributes
    {
        $forEntries = self::entriesOf($request, $this->headers->for);

        $index = $this->lastUntrustedIndex($forEntries);
        // no untrusted entry (index past the end) resolves nothing, as does an untrusted one which is not a valid ip
        $clientIp = self::asIp($forEntries[$index] ?? '');

        if (null === $clientIp) {
            return new TrustedProxyAttributes();
        }

        $forCount = \count($forEntries);

        $scheme = self::alignedEntry(self::entriesOf($request, $this->headers->proto), $index, $forCount);
        $host = self::alignedEntry(self::entriesOf($request, $this->headers->host), $index, $forCount);

        return new TrustedProxyAttributes($clientIp, self::asScheme($scheme), self::asHost($host));
    }

    /**
     * The entry at the same position as the client ip within the `for` header, if the counts are equal, the last one
     * otherwise. Equal counts only prove that the proxies append to this header as well as to `for`, not that the
     * entry is trustworthy: a proxy passing this header through untouched lets the client pad it to align the counts,
     * which is why the proxies must set (or strip) all the forwarded headers (see TrustedProxyMiddleware).
     *
     * @param list<string> $entries
     */
    private static function alignedEntry(array $entries, int $index, int $forCount): string
    {
        $count = \count($entries);

        return $count === $forCount ? $entries[$index] : ($entries[$count - 1] ?? '');
    }

    /**
     * @param list<string> $entries
     *
     * @return int the index of the last untrusted entry, the count (one past the end) if there is none
     */
    private function lastUntrustedIndex(array $entries): int
    {
        $count = \count($entries);

        for ($i = $count - 1; $i >= 0; --$i) {
            if (!$this->isTrustedProxy($entries[$i])) {
                return $i;
            }
        }

        return $count;
    }

    /**
     * @return array{0: string, 1: string}
     */
    private static function parseSubnet(mixed $subnet): array
    {
        $invalid = \sprintf(
            'trustedProxies must contain valid ips or cidrs, %s given',
            \is_string($subnet) ? '"'.$subnet.'"' : get_debug_type($subnet)
        );

        // trimmed, as config often comes out of env vars
        if (!\is_string($subnet) || 1 !== preg_match('#^([^/]+)(?:/(\d+))?\z#', trim($subnet), $matches)) {
            throw new \InvalidArgumentException($invalid);
        }

        $packed = self::packIp($matches[1]);

        if (null === $packed) {
            throw new \InvalidArgumentException($invalid);
        }

        $maxPrefix = \strlen($packed) * 8;
        $prefix = (int) ($matches[2] ?? $maxPrefix);

        if ($prefix > $maxPrefix) {
            throw new \InvalidArgumentException($invalid);
        }

        if (0 === $prefix) {
            throw new \InvalidArgumentException(
                \sprintf('trustedProxies must not contain a subnet matching every ip, "%s" given', $subnet)
            );
        }

        // the prefix as a byte mask: full bytes of ones, the remaining bits within the next byte, zeros after
        $mask = str_repeat("\xFF", intdiv($prefix, 8));

        if (0 !== $prefix % 8) {
            $mask .= pack('C', 0x100 - (1 << (8 - $prefix % 8)));
        }

        $mask = str_pad($mask, \strlen($packed), "\0");

        return [$packed & $mask, $mask];
    }

    /**
     * Packs a valid ip into its binary form, ipv4 mapped ipv6 addresses (`::ffff:10.0.0.1`) as ipv4, so that they
     * match ipv4 subnets. Null for everything which is not a valid ip.
     */
    private static function packIp(string $ip): ?string
    {
        $packed = false === filter_var($ip, FILTER_VALIDATE_IP) ? false : inet_pton($ip);

        if (false === $packed) {
            return null;
        }

        if (16 === \strlen($packed) && str_starts_with($packed, "\0\0\0\0\0\0\0\0\0\0\xff\xff")) {
            return substr($packed, 12);
        }

        return $packed;
    }

    // non ip entries are never trusted, the resolver rejects them as client ip afterwards
    private function isTrustedProxy(string $ip): bool
    {
        $packed = self::packIp($ip);

        if (null === $packed) {
            return false;
        }

        foreach ($this->subnets as [$network, $mask]) {
            // the length check keeps an ipv6 address from matching an ipv4 subnet: `&` truncates to the shorter operand
            if (\strlen($mask) === \strlen($packed) && ($packed & $mask) === $network) {
                return true;
            }
        }

        return false;
    }

    /**
     * The address of the connection, a port gets stripped (`10.0.0.1:54321`, `[::1]:54321`, as some servers provide
     * it), so that it can be matched against the trusted proxies.
     */
    private function remoteAddress(ServerRequestInterface $request): ?string
    {
        $remoteAddress = $request->getAttribute(self::REMOTE_ADDRESS_ATTRIBUTE)
            ?? $request->getServerParams()[self::REMOTE_ADDR_SERVER_PARAM]
            ?? null;

        if (!\is_string($remoteAddress)) {
            return null;
        }

        // `[ipv6]:port` or `ipv4:port`
        if (1 === preg_match('/^(?:\[([^\]]+)\]|([^:]+)):\d+\z/', $remoteAddress, $matches)) {
            return '' !== $matches[1] ? $matches[1] : $matches[2];
        }

        return $remoteAddress;
    }

    /**
     * @return list<string>
     */
    private static function entriesOf(ServerRequestInterface $request, ?string $name): array
    {
        if (null === $name) {
            return [];
        }

        // a missing header is a single empty entry, which never resolves to anything
        return array_map(trim(...), explode(',', $request->getHeaderLine($name)));
    }

    /**
     * Only a valid ip is a client ip, everything else (blank, "unknown", ip:port, junk) resolves nothing. The ip gets
     * canonicalized, ipv4 mapped ipv6 addresses as ipv4.
     */
    private static function asIp(string $entry): ?string
    {
        $packed = self::packIp($entry);

        if (null === $packed) {
            return null;
        }

        $ip = inet_ntop($packed);

        return false === $ip ? null : $ip;
    }

    private static function asScheme(string $entry): ?string
    {
        $scheme = strtolower($entry);

        return \in_array($scheme, self::SCHEMES, true) ? $scheme : null;
    }

    private static function asHost(string $entry): ?string
    {
        if (1 !== preg_match(self::HOST_PATTERN, $entry, $matches)) {
            return null;
        }

        $port = $matches['port'] ?? null;
        $ipv6 = $matches['ipv6'] ?? '';

        $valid = (null === $port || ($port >= self::MIN_PORT && $port <= self::MAX_PORT))
            && ('' === $ipv6 || false !== filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));

        return $valid ? $entry : null;
    }
}
