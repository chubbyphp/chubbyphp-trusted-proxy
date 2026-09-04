<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Unit;

use Chubbyphp\TrustedProxy\ForwardedHeaders;
use Chubbyphp\TrustedProxy\ForwardedResolver;
use Chubbyphp\TrustedProxy\TrustedProxyAttributes;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @covers \Chubbyphp\TrustedProxy\ForwardedResolver
 *
 * @internal
 */
final class ForwardedResolverTest extends TestCase
{
    // documentation ranges (rfc 5737) and a private range (rfc 1918), never routed
    private const string CLIENT_IP = '203.0.113.1';
    private const string OTHER_CLIENT_IP = '198.51.100.1';
    private const string PROXY_IP = '10.0.0.1';
    private const string PROXY_CIDR = '10.0.0.0/8';

    public function testWithEmptyTrustedProxies(): void
    {
        $create = static fn (): ForwardedResolver => new ForwardedResolver([]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('trustedProxies must not be empty');

        $create();
    }

    /**
     * @param list<mixed> $trustedProxies
     */
    #[DataProvider('provideWithInvalidTrustedProxiesCases')]
    public function testWithInvalidTrustedProxies(array $trustedProxies, string $message): void
    {
        $create = static fn (): ForwardedResolver => new ForwardedResolver($trustedProxies);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $create();
    }

    /**
     * @return iterable<string, array{0: list<mixed>, 1: string}>
     */
    public static function provideWithInvalidTrustedProxiesCases(): iterable
    {
        yield 'non string' => [[10], 'trustedProxies must contain valid ips or cidrs, int given'];

        yield 'junk' => [['junk'], 'trustedProxies must contain valid ips or cidrs, "junk" given'];

        yield 'blank' => [[' '], 'trustedProxies must contain valid ips or cidrs, " " given'];

        yield 'out of range octet' => [['10.0.0.256'], 'trustedProxies must contain valid ips or cidrs, "10.0.0.256" given'];

        yield 'ip with port' => [[self::PROXY_IP.':8080'], 'trustedProxies must contain valid ips or cidrs, "'.self::PROXY_IP.':8080" given'];

        yield 'double slash' => [[self::PROXY_CIDR.'/8'], 'trustedProxies must contain valid ips or cidrs, "'.self::PROXY_CIDR.'/8" given'];

        yield 'empty prefix' => [['10.0.0.0/'], 'trustedProxies must contain valid ips or cidrs, "10.0.0.0/" given'];

        yield 'non numeric prefix' => [['10.0.0.0/x'], 'trustedProxies must contain valid ips or cidrs, "10.0.0.0/x" given'];

        yield 'negative prefix' => [['10.0.0.0/-1'], 'trustedProxies must contain valid ips or cidrs, "10.0.0.0/-1" given'];

        yield 'float prefix' => [[self::PROXY_CIDR.'.5'], 'trustedProxies must contain valid ips or cidrs, "'.self::PROXY_CIDR.'.5" given'];

        yield 'ipv4 prefix too large' => [['10.0.0.0/33'], 'trustedProxies must contain valid ips or cidrs, "10.0.0.0/33" given'];

        yield 'ipv6 prefix too large' => [['::1/129'], 'trustedProxies must contain valid ips or cidrs, "::1/129" given'];

        yield 'ipv4 match all' => [['0.0.0.0/0'], 'trustedProxies must not contain a subnet matching every ip, "0.0.0.0/0" given'];

        yield 'ipv6 match all' => [['::/0'], 'trustedProxies must not contain a subnet matching every ip, "::/0" given'];

        yield 'match all with leading zeros' => [['::/000'], 'trustedProxies must not contain a subnet matching every ip, "::/000" given'];

        yield 'valid before invalid' => [[self::PROXY_CIDR, 'junk'], 'trustedProxies must contain valid ips or cidrs, "junk" given'];
    }

    public function testWithUntrimmedTrustedProxies(): void
    {
        $resolver = new ForwardedResolver([' '.self::PROXY_CIDR.' ', "\t::1\n"]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => self::CLIENT_IP.', '.self::PROXY_IP.', ::1']))
        );
    }

    public function testWithoutHeaders(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(new TrustedProxyAttributes(), $resolver->resolve(self::createRequest([])));
    }

    public function testWithoutForHeaderTheOtherHeadersGetIgnored(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(),
            $resolver->resolve(self::createRequest(['X-Forwarded-Proto' => 'https', 'X-Forwarded-Host' => 'example.com']))
        );
    }

    #[DataProvider('provideWithForHeaderCases')]
    public function testWithForHeader(string $for, ?string $clientIp): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR, '192.168.1.1', '192.168.1.1/32', '::1', 'fd00::/8', '2001:db8:1:2::/64']);

        self::assertEquals(
            new TrustedProxyAttributes($clientIp),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => $for]))
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: null|string}>
     */
    public static function provideWithForHeaderCases(): iterable
    {
        yield 'empty' => ['', null];

        yield 'blank' => ['  ', null];

        yield 'empty entries' => [',,', null];

        yield 'blank last entry' => [self::CLIENT_IP.', ', null];

        yield 'single untrusted' => [self::CLIENT_IP, self::CLIENT_IP];

        yield 'single trusted' => [self::PROXY_IP, null];

        yield 'only trusted' => [self::PROXY_IP.', 10.0.0.2', null];

        yield 'untrusted then trusted' => [self::CLIENT_IP.', '.self::PROXY_IP, self::CLIENT_IP];

        yield 'untrusted then multiple trusted' => [self::CLIENT_IP.', 10.255.255.255, '.self::PROXY_IP, self::CLIENT_IP];

        yield 'first untrusted from the right' => [self::OTHER_CLIENT_IP.', '.self::CLIENT_IP.', '.self::PROXY_IP, self::CLIENT_IP];

        yield 'untrusted last' => [self::CLIENT_IP.', 11.0.0.1', '11.0.0.1'];

        yield 'trusted at the boundaries of the cidr' => [self::CLIENT_IP.', 10.0.0.0, 10.255.255.255', self::CLIENT_IP];

        yield 'untrusted just outside the cidr' => [self::CLIENT_IP.', 9.255.255.255', '9.255.255.255'];

        yield 'untrimmed entries' => [' '.self::CLIENT_IP.' ,  '.self::PROXY_IP.' ', self::CLIENT_IP];

        yield 'trusted single ipv4' => [self::CLIENT_IP.', 192.168.1.1', self::CLIENT_IP];

        yield 'untrusted ipv4 next to the single one' => [self::CLIENT_IP.', 192.168.1.2', '192.168.1.2'];

        yield 'trusted ipv6 single' => [self::CLIENT_IP.', ::1', self::CLIENT_IP];

        yield 'trusted ipv6 cidr' => [self::CLIENT_IP.', fd00::1, fd00:ffff::1', self::CLIENT_IP];

        yield 'untrusted ipv6' => [self::CLIENT_IP.', fe80::1', 'fe80::1'];

        yield 'untrusted ipv6 next to loopback' => [self::CLIENT_IP.', ::2', '::2'];

        yield 'untrusted ipv6 just outside the cidr' => [self::CLIENT_IP.', fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'];

        yield 'ipv4 mapped ipv6 trusted' => [self::CLIENT_IP.', ::ffff:'.self::PROXY_IP, self::CLIENT_IP];

        yield 'ipv4 mapped ipv6 untrusted resolves the ipv4' => [self::CLIENT_IP.', ::ffff:11.0.0.1', '11.0.0.1'];

        yield 'ipv4 not matching an ipv6 subnet with the same bytes' => [self::CLIENT_IP.', 253.0.0.1', '253.0.0.1'];

        yield 'unknown in the middle' => [self::CLIENT_IP.', unknown, '.self::PROXY_IP, null];

        yield 'unknown first' => ['unknown, '.self::CLIENT_IP.', '.self::PROXY_IP, self::CLIENT_IP];

        yield 'ipv4 with port' => [self::CLIENT_IP.':54321, '.self::PROXY_IP, null];

        yield 'ipv6 with port' => ['[2001:db8::1]:443, '.self::PROXY_IP, null];

        yield 'junk' => ['junk, '.self::PROXY_IP, null];

        yield 'ipv6 trusted within a multi byte cidr' => [self::CLIENT_IP.', 2001:db8:1:2:ffff:ffff:ffff:ffff', self::CLIENT_IP];

        yield 'ipv6 untrusted just outside a multi byte cidr' => [self::CLIENT_IP.', 2001:db8:1:3::', '2001:db8:1:3::'];

        yield 'ipv6 gets canonicalized' => [self::CLIENT_IP.', 2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'];

        yield 'ipv4 mapped ipv6 client gets canonicalized' => ['::ffff:'.self::CLIENT_IP.', '.self::PROXY_IP, self::CLIENT_IP];

        yield 'uppercase ipv6 gets canonicalized' => ['2001:DB8:0000:0:0::0001, '.self::PROXY_IP, '2001:db8::1'];

        yield 'uppercase ipv4 mapped ipv6 gets canonicalized' => ['::FFFF:11.0.0.1, '.self::PROXY_IP, '11.0.0.1'];

        yield 'uppercase ipv4 mapped ipv6 trusted' => [self::CLIENT_IP.', ::FFFF:'.self::PROXY_IP, self::CLIENT_IP];

        yield 'ipv6 with zone id is not a valid ip' => ['fe80::1%eth0, '.self::PROXY_IP, null];

        yield 'trusted ipv6 with zone id is not trusted' => [self::CLIENT_IP.', fd00::1%eth0', null];
    }

    public function testWithNonIpClientEntryTheOtherHeadersGetIgnored(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => 'unknown, '.self::PROXY_IP,
                'X-Forwarded-Proto' => 'https',
                'X-Forwarded-Host' => 'example.com',
            ]))
        );
    }

    public function testWithPartialByteCidr(): void
    {
        $resolver = new ForwardedResolver(['203.0.113.64/27']);

        $serverParams = ['REMOTE_ADDR' => '203.0.113.64'];

        self::assertEquals(
            new TrustedProxyAttributes('203.0.113.63'),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => '203.0.113.63, 203.0.113.64, 203.0.113.95'], [], $serverParams))
        );
        self::assertEquals(
            new TrustedProxyAttributes('203.0.113.96'),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => '203.0.113.64, 203.0.113.96'], [], $serverParams))
        );
        self::assertEquals(
            new TrustedProxyAttributes('203.0.113.0'),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => '203.0.113.0, 203.0.113.64'], [], $serverParams))
        );
        self::assertEquals(
            new TrustedProxyAttributes('203.0.113.32'),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => '203.0.113.32, 203.0.113.64'], [], $serverParams))
        );
    }

    public function testWithMultipleForHeaderLines(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        $request = (new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => self::PROXY_IP]))
            ->withAddedHeader('X-Forwarded-For', self::CLIENT_IP)
            ->withAddedHeader('X-Forwarded-For', self::PROXY_IP)
        ;

        self::assertEquals(new TrustedProxyAttributes(self::CLIENT_IP), $resolver->resolve($request));
    }

    public function testWithAllHeadersAlignedEntries(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https', 'example.com'),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => 'spoofed, '.self::CLIENT_IP.', '.self::PROXY_IP,
                'X-Forwarded-Proto' => 'spoofed, HTTPS, http',
                'X-Forwarded-Host' => 'spoofed, example.com, internal',
            ]))
        );
    }

    public function testWithAllHeadersNotAlignedEntriesTheLastEntry(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https', 'example.com'),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => 'spoofed, '.self::CLIENT_IP.', '.self::PROXY_IP,
                'X-Forwarded-Proto' => 'https',
                'X-Forwarded-Host' => 'spoofed, example.com',
            ]))
        );
    }

    public function testWithMoreProtoAndHostEntriesThanForEntriesTheLastEntry(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https', 'example.com'),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => self::CLIENT_IP.', '.self::PROXY_IP,
                'X-Forwarded-Proto' => 'spoofed, http, https',
                'X-Forwarded-Host' => 'spoofed, internal, example.com',
            ]))
        );
    }

    public function testWithBlankProtoAndHostEntries(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => self::CLIENT_IP,
                'X-Forwarded-Proto' => '',
                'X-Forwarded-Host' => ' ',
            ]))
        );

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => self::CLIENT_IP.', '.self::PROXY_IP,
                'X-Forwarded-Proto' => ', https',
                'X-Forwarded-Host' => ', example.com',
            ]))
        );
    }

    #[DataProvider('provideWithInvalidProtoAndHostEntriesCases')]
    public function testWithInvalidProtoAndHostEntries(string $proto, string $host): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => self::CLIENT_IP,
                'X-Forwarded-Proto' => $proto,
                'X-Forwarded-Host' => $host,
            ]))
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideWithInvalidProtoAndHostEntriesCases(): iterable
    {
        yield 'unknown scheme, host with space' => ['javascript', 'example com'];

        yield 'scheme with tab inside, host with slash' => ["ht\ttps", 'example.com/path'];

        yield 'scheme with junk, host with scheme' => ['https;', 'https://example.com'];

        yield 'partial scheme, host with credentials' => ['http-', 'user@example.com'];

        yield 'data scheme, host with non ascii' => ['data', 'exämple.com'];

        yield 'ws scheme, host with empty label' => ['ws', 'example..com'];

        yield 'wss scheme, host starting with a hyphen' => ['wss', '-example.com'];

        yield 'https with space inside, unbracketed ipv6' => ['ht tps', '2001:db8::1'];

        yield 'https with junk, bracketed junk' => ['https:', '[junk]'];

        yield 'https with trailing junk, port too long' => ['https\x00', 'example.com:123456'];

        yield 'https with slashes, port out of range' => ['https://', 'example.com:65536'];

        yield 'http with space inside, bracketed ipv4' => ['h ttp', '[203.0.113.1]'];

        yield 'https uppercase junk, bracketed invalid ipv6' => ['HTTPS;', '[2001:db8::1::2]'];

        yield 'https with a trailing dot, port zero' => ['https.', 'example.com:0'];
    }

    #[DataProvider('provideWithValidHostEntriesCases')]
    public function testWithValidHostEntries(string $host): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https', $host),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => self::CLIENT_IP,
                'X-Forwarded-Proto' => 'HTTPS',
                'X-Forwarded-Host' => $host,
            ]))
        );
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function provideWithValidHostEntriesCases(): iterable
    {
        yield 'hostname' => ['example.com'];

        yield 'hostname with port' => ['example.com:8443'];

        yield 'single label' => ['localhost'];

        yield 'fully qualified' => ['example.com.'];

        yield 'punycode' => ['xn--exmple-cua.com'];

        yield 'hyphen inside a label' => ['my-example.com'];

        yield 'ipv4' => ['203.0.113.1'];

        yield 'ipv4 with port' => ['203.0.113.1:8080'];

        yield 'bracketed ipv6' => ['[2001:db8::1]'];

        yield 'bracketed ipv6 with port' => ['[2001:db8::1]:8080'];

        yield 'bracketed ipv4 mapped ipv6' => ['[::ffff:203.0.113.1]'];

        yield 'hostname with the highest port' => ['example.com:65535'];

        yield 'hostname with the lowest port' => ['example.com:1'];
    }

    public function testWithoutRemoteAddressNothingGetsResolved(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP, 'X-Forwarded-Proto' => 'https', 'X-Forwarded-Host' => 'example.com'],
                [],
                []
            ))
        );
    }

    public function testWithoutRemoteAddressNotRequiredTheHeadersGetUsed(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR], null, false);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https', 'example.com'),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP, 'X-Forwarded-Proto' => 'https', 'X-Forwarded-Host' => 'example.com'],
                [],
                []
            ))
        );

        // an untrusted connection still wins over the headers
        self::assertEquals(
            new TrustedProxyAttributes(self::OTHER_CLIENT_IP),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP],
                [],
                ['REMOTE_ADDR' => self::OTHER_CLIENT_IP]
            ))
        );
    }

    #[DataProvider('provideWithRemoteAddressWithPortCases')]
    public function testWithRemoteAddressWithPort(string $remoteAddress, ?string $clientIp): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR, '::1']);

        self::assertEquals(
            new TrustedProxyAttributes($clientIp),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => self::CLIENT_IP], ['remoteAddress' => $remoteAddress]))
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: null|string}>
     */
    public static function provideWithRemoteAddressWithPortCases(): iterable
    {
        yield 'trusted ipv4 with port' => [self::PROXY_IP.':54321', self::CLIENT_IP];

        yield 'trusted ipv6 with port' => ['[::1]:54321', self::CLIENT_IP];

        yield 'untrusted ipv4 with port' => [self::OTHER_CLIENT_IP.':54321', self::OTHER_CLIENT_IP];

        yield 'untrusted ipv6 with port' => ['[2001:db8::1]:54321', '2001:db8::1'];

        yield 'untrusted ipv4 mapped ipv6 with port' => ['[::ffff:'.self::OTHER_CLIENT_IP.']:54321', self::OTHER_CLIENT_IP];

        yield 'unbracketed ipv6 stays as it is' => ['2001:db8::1', '2001:db8::1'];

        yield 'ipv4 with non numeric port' => [self::PROXY_IP.':port', null];

        yield 'ipv4 with empty port' => [self::PROXY_IP.':', null];

        yield 'bracketed ipv6 without port' => ['[::1]', null];

        yield 'bracketed ipv6 with empty port' => ['[::1]:', null];

        yield 'unclosed bracket' => ['[::1:54321', null];

        yield 'port with trailing junk' => [self::PROXY_IP.':54321x', null];
    }

    public function testWithTrustedRemoteAddressAttributeTheHeadersGetUsed(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https'),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP, 'X-Forwarded-Proto' => 'https'],
                ['remoteAddress' => self::PROXY_IP]
            ))
        );
    }

    public function testWithTrustedRemoteAddrServerParamTheHeadersGetUsed(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https'),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP, 'X-Forwarded-Proto' => 'https'],
                [],
                ['REMOTE_ADDR' => self::PROXY_IP]
            ))
        );
    }

    public function testWithUntrustedRemoteAddressAttributeTheHeadersGetIgnored(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::OTHER_CLIENT_IP),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP, 'X-Forwarded-Proto' => 'https'],
                ['remoteAddress' => self::OTHER_CLIENT_IP]
            ))
        );

        self::assertEquals(
            new TrustedProxyAttributes(),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => self::CLIENT_IP], ['remoteAddress' => '']))
        );

        self::assertEquals(
            new TrustedProxyAttributes(),
            $resolver->resolve(self::createRequest(['X-Forwarded-For' => self::CLIENT_IP], ['remoteAddress' => 'not-an-ip']))
        );
    }

    public function testWithUntrustedRemoteAddrServerParamTheHeadersGetIgnored(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::OTHER_CLIENT_IP),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP, 'X-Forwarded-Proto' => 'https'],
                [],
                ['REMOTE_ADDR' => self::OTHER_CLIENT_IP]
            ))
        );
    }

    public function testTheRemoteAddressAttributeWinsOverTheRemoteAddrServerParam(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP],
                ['remoteAddress' => self::PROXY_IP],
                ['REMOTE_ADDR' => self::OTHER_CLIENT_IP]
            ))
        );

        self::assertEquals(
            new TrustedProxyAttributes(self::OTHER_CLIENT_IP),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP],
                ['remoteAddress' => self::OTHER_CLIENT_IP],
                ['REMOTE_ADDR' => self::PROXY_IP]
            ))
        );
    }

    #[DataProvider('provideWithNonStringRemoteAddressNothingGetsResolvedCases')]
    public function testWithNonStringRemoteAddressNothingGetsResolved(mixed $remoteAddress): void
    {
        // even with the address not required: a broken address is set, so there is no fallback to the headers
        foreach ([true, false] as $requireRemoteAddress) {
            $resolver = new ForwardedResolver([self::PROXY_CIDR], null, $requireRemoteAddress);

            self::assertEquals(
                new TrustedProxyAttributes(),
                $resolver->resolve(self::createRequest(['X-Forwarded-For' => self::CLIENT_IP], ['remoteAddress' => $remoteAddress], []))
            );

            self::assertEquals(
                new TrustedProxyAttributes(),
                $resolver->resolve(self::createRequest(['X-Forwarded-For' => self::CLIENT_IP], [], ['REMOTE_ADDR' => $remoteAddress]))
            );
        }
    }

    /**
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideWithNonStringRemoteAddressNothingGetsResolvedCases(): iterable
    {
        yield 'int' => [1];

        yield 'bool' => [true];

        yield 'array' => [[self::PROXY_IP]];

        yield 'object' => [(object) ['address' => self::PROXY_IP]];
    }

    public function testWithNullRemoteAddressAttributeTheServerParamGetsUsed(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP),
            $resolver->resolve(self::createRequest(
                ['X-Forwarded-For' => self::CLIENT_IP],
                ['remoteAddress' => null],
                ['REMOTE_ADDR' => self::PROXY_IP]
            ))
        );
    }

    public function testWithCustomHeaders(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR], new ForwardedHeaders('X-Real-IP', 'X-Scheme', null));

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https'),
            $resolver->resolve(self::createRequest([
                'X-Forwarded-For' => 'spoofed',
                'X-Real-IP' => self::CLIENT_IP,
                'X-Scheme' => 'https',
                'X-Forwarded-Host' => 'spoofed',
            ]))
        );
    }

    public function testWithCaseInsensitiveHeaders(): void
    {
        $resolver = new ForwardedResolver([self::PROXY_CIDR]);

        self::assertEquals(
            new TrustedProxyAttributes(self::CLIENT_IP, 'https', 'example.com'),
            $resolver->resolve(self::createRequest([
                'x-forwarded-for' => self::CLIENT_IP.', '.self::PROXY_IP,
                'x-forwarded-proto' => 'https',
                'x-forwarded-host' => 'example.com',
            ]))
        );
    }

    /**
     * @param array<string, string>     $headers
     * @param array<string, mixed>      $attributes
     * @param null|array<string, mixed> $serverParams
     */
    private static function createRequest(
        array $headers,
        array $attributes = [],
        ?array $serverParams = null,
    ): ServerRequestInterface {
        // a trusted connection by default, so that the headers get used
        $request = new ServerRequest('GET', '/', $headers, null, '1.1', $serverParams ?? ['REMOTE_ADDR' => self::PROXY_IP]);

        foreach ($attributes as $name => $value) {
            $request = $request->withAttribute($name, $value);
        }

        return $request;
    }
}
