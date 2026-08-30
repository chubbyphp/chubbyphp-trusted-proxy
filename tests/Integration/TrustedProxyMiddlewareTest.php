<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Integration;

use Chubbyphp\TrustedProxy\ForwardedResolver;
use Chubbyphp\TrustedProxy\TrustedProxyAttributes;
use Chubbyphp\TrustedProxy\TrustedProxyMiddleware;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @coversNothing
 *
 * @internal
 */
final class TrustedProxyMiddlewareTest extends TestCase
{
    public function testThroughATrustedProxy(): void
    {
        $request = (new ServerRequest('GET', '/', [
            'X-Forwarded-For' => 'spoofed, 203.0.113.1, 10.0.0.1',
            'X-Forwarded-Proto' => 'spoofed, https, http',
            'X-Forwarded-Host' => 'spoofed, example.com, internal',
        ], null, '1.1', ['REMOTE_ADDR' => '10.0.0.2']))
            ->withAttribute(TrustedProxyAttributes::CLIENT_IP, 'stale')
        ;

        self::assertSame(
            ['clientIp' => '203.0.113.1', 'scheme' => 'https', 'host' => 'example.com'],
            self::process($request)
        );
    }

    public function testFromAnUntrustedConnection(): void
    {
        $request = new ServerRequest('GET', '/', [
            'X-Forwarded-For' => '203.0.113.1',
            'X-Forwarded-Proto' => 'https',
            'X-Forwarded-Host' => 'example.com',
        ], null, '1.1', ['REMOTE_ADDR' => '198.51.100.1']);

        self::assertSame(['clientIp' => '198.51.100.1', 'scheme' => null, 'host' => null], self::process($request));
    }

    public function testWithoutConnectionAddress(): void
    {
        $request = (new ServerRequest('GET', '/', ['X-Forwarded-For' => '203.0.113.1']))
            ->withAttribute(TrustedProxyAttributes::CLIENT_IP, 'stale')
        ;

        self::assertSame(['clientIp' => null, 'scheme' => null, 'host' => null], self::process($request));
    }

    /**
     * @return array{clientIp: mixed, scheme: mixed, host: mixed}
     */
    private static function process(ServerRequestInterface $request): array
    {
        $handler = new class implements RequestHandlerInterface {
            /** @var array<string, mixed> */
            public array $attributes = [];

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->attributes = $request->getAttributes();

                return new Response(204);
            }
        };

        $response = (new TrustedProxyMiddleware(new ForwardedResolver(['10.0.0.0/8'])))->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());

        return [
            'clientIp' => $handler->attributes[TrustedProxyAttributes::CLIENT_IP] ?? null,
            'scheme' => $handler->attributes[TrustedProxyAttributes::SCHEME] ?? null,
            'host' => $handler->attributes[TrustedProxyAttributes::HOST] ?? null,
        ];
    }
}
