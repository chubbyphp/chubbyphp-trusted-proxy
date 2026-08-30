<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Unit;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockMethod\WithReturnSelf;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\TrustedProxy\ForwardedResolverInterface;
use Chubbyphp\TrustedProxy\TrustedProxyAttributes;
use Chubbyphp\TrustedProxy\TrustedProxyMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @covers \Chubbyphp\TrustedProxy\TrustedProxyMiddleware
 *
 * @internal
 */
final class TrustedProxyMiddlewareTest extends TestCase
{
    public function testWithResolvedValuesTheAttributesGetSet(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ServerRequestInterface $request */
        $request = $builder->create(ServerRequestInterface::class, [
            new WithReturnSelf('withAttribute', ['clientIp', '203.0.113.1']),
            new WithReturnSelf('withAttribute', ['scheme', 'https']),
            new WithReturnSelf('withAttribute', ['host', 'example.com']),
        ]);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, []);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, [
            new WithReturn('handle', [$request], $response),
        ]);

        /** @var ForwardedResolverInterface $forwardedResolver */
        $forwardedResolver = $builder->create(ForwardedResolverInterface::class, [
            new WithReturn('resolve', [$request], new TrustedProxyAttributes('203.0.113.1', 'https', 'example.com')),
        ]);

        $middleware = new TrustedProxyMiddleware($forwardedResolver);

        self::assertSame($response, $middleware->process($request, $handler));
    }

    public function testWithoutResolvedValuesTheAttributesGetReset(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ServerRequestInterface $request */
        $request = $builder->create(ServerRequestInterface::class, [
            new WithReturnSelf('withAttribute', ['clientIp', null]),
            new WithReturnSelf('withAttribute', ['scheme', null]),
            new WithReturnSelf('withAttribute', ['host', null]),
        ]);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, []);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, [
            new WithReturn('handle', [$request], $response),
        ]);

        /** @var ForwardedResolverInterface $forwardedResolver */
        $forwardedResolver = $builder->create(ForwardedResolverInterface::class, [
            new WithReturn('resolve', [$request], new TrustedProxyAttributes()),
        ]);

        $middleware = new TrustedProxyMiddleware($forwardedResolver);

        self::assertSame($response, $middleware->process($request, $handler));
    }
}
