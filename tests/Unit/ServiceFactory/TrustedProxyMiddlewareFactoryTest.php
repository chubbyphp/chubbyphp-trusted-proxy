<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Unit\ServiceFactory;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\TrustedProxy\ForwardedResolver;
use Chubbyphp\TrustedProxy\ForwardedResolverInterface;
use Chubbyphp\TrustedProxy\ServiceFactory\TrustedProxyMiddlewareFactory;
use Chubbyphp\TrustedProxy\TrustedProxyMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * @covers \Chubbyphp\TrustedProxy\ServiceFactory\TrustedProxyMiddlewareFactory
 *
 * @internal
 */
final class TrustedProxyMiddlewareFactoryTest extends TestCase
{
    public function testInvoke(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ForwardedResolverInterface $forwardedResolver */
        $forwardedResolver = $builder->create(ForwardedResolverInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('has', [ForwardedResolverInterface::class], true),
            new WithReturn('get', [ForwardedResolverInterface::class], $forwardedResolver),
        ]);

        $factory = new TrustedProxyMiddlewareFactory();

        $service = $factory($container);

        self::assertInstanceOf(TrustedProxyMiddleware::class, $service);

        self::assertEquals(new TrustedProxyMiddleware($forwardedResolver), $service);
    }

    public function testInvokeWithoutRegisteredResolver(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('has', [ForwardedResolverInterface::class], false),
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => ['10.0.0.0/8'],
                    ],
                ],
            ]),
        ]);

        $factory = new TrustedProxyMiddlewareFactory();

        $service = $factory($container);

        self::assertInstanceOf(TrustedProxyMiddleware::class, $service);

        self::assertEquals(new TrustedProxyMiddleware(new ForwardedResolver(['10.0.0.0/8'])), $service);
    }

    public function testCallStatic(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ForwardedResolverInterface $forwardedResolver */
        $forwardedResolver = $builder->create(ForwardedResolverInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('has', [ForwardedResolverInterface::class.'default'], true),
            new WithReturn('get', [ForwardedResolverInterface::class.'default'], $forwardedResolver),
        ]);

        $factory = [TrustedProxyMiddlewareFactory::class, 'default'];

        $service = $factory($container);

        self::assertInstanceOf(TrustedProxyMiddleware::class, $service);

        self::assertEquals(new TrustedProxyMiddleware($forwardedResolver), $service);
    }
}
