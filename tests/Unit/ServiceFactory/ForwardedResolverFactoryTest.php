<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Unit\ServiceFactory;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\TrustedProxy\ForwardedHeaders;
use Chubbyphp\TrustedProxy\ForwardedResolver;
use Chubbyphp\TrustedProxy\ServiceFactory\ForwardedResolverFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * @covers \Chubbyphp\TrustedProxy\ServiceFactory\ForwardedResolverFactory
 *
 * @internal
 */
final class ForwardedResolverFactoryTest extends TestCase
{
    public function testInvoke(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => ['10.0.0.0/8', '::1'],
                    ],
                ],
            ]),
        ]);

        $factory = new ForwardedResolverFactory();

        $service = $factory($container);

        self::assertInstanceOf(ForwardedResolver::class, $service);

        self::assertEquals(new ForwardedResolver(['10.0.0.0/8', '::1']), $service);
    }

    public function testInvokeWithHeaders(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => ['10.0.0.0/8'],
                        'headers' => ['for' => 'X-Real-IP', 'proto' => 'X-Scheme', 'host' => null],
                    ],
                ],
            ]),
        ]);

        $factory = new ForwardedResolverFactory();

        $service = $factory($container);

        self::assertInstanceOf(ForwardedResolver::class, $service);

        self::assertEquals(new ForwardedResolver(['10.0.0.0/8'], new ForwardedHeaders('X-Real-IP', 'X-Scheme', null)), $service);
    }

    public function testInvokeWithoutRequireRemoteAddress(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => ['10.0.0.0/8'],
                        'requireRemoteAddress' => false,
                    ],
                ],
            ]),
        ]);

        $factory = new ForwardedResolverFactory();

        $service = $factory($container);

        self::assertEquals(new ForwardedResolver(['10.0.0.0/8'], null, false), $service);
    }

    /**
     * @param array<string, mixed> $trustedProxyConfig
     */
    #[DataProvider('provideInvokeWithInvalidConfigCases')]
    public function testInvokeWithInvalidConfig(array $trustedProxyConfig, string $message, bool $wrapped = false): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], ['chubbyphp' => ['trustedProxy' => $trustedProxyConfig]]),
        ]);

        $factory = new ForwardedResolverFactory();

        try {
            $factory($container);
            self::fail('expected an exception');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('config.chubbyphp.trustedProxy.'.$message, $e->getMessage());
            self::assertSame(0, $e->getCode());
            self::assertSame($wrapped, null !== $e->getPrevious());
        }
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2?: bool}>
     */
    public static function provideInvokeWithInvalidConfigCases(): iterable
    {
        $trustedProxies = ['10.0.0.0/8'];

        yield 'unknown header key' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['For' => 'X-Real-IP']],
            'headers must be an array with the keys for, proto and host, key "For" given',
        ];

        yield 'list as headers' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['X-Real-IP']],
            'headers must be an array with the keys for, proto and host, key "0" given',
        ];

        yield 'null for' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['for' => null]],
            'headers.for must be a string, null given',
        ];

        yield 'array for' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['for' => ['X-Real-IP']]],
            'headers.for must be a string, array given',
        ];

        yield 'int proto' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['proto' => 1]],
            'headers.proto must be a string or null, int given',
        ];

        yield 'bool host' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['host' => false]],
            'headers.host must be a string or null, bool given',
        ];

        yield 'invalid header name' => [
            ['trustedProxies' => $trustedProxies, 'headers' => ['for' => 'X Real IP']],
            'headers.for must be a valid header name, "X Real IP" given',
            true,
        ];

        yield 'invalid trusted proxy' => [
            ['trustedProxies' => ['junk']],
            'trustedProxies must contain valid ips or cidrs, "junk" given',
            true,
        ];

        yield 'string requireRemoteAddress' => [
            ['trustedProxies' => $trustedProxies, 'requireRemoteAddress' => 'false'],
            'requireRemoteAddress must be a bool, string given',
        ];
    }

    public function testInvokeWithoutTrustedProxies(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], []),
        ]);

        $factory = new ForwardedResolverFactory();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'config.chubbyphp.trustedProxy.trustedProxies must be an array of ips or cidrs, null given'
        );

        $factory($container);
    }

    public function testInvokeWithInvalidTrustedProxies(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => '10.0.0.0/8',
                    ],
                ],
            ]),
        ]);

        $factory = new ForwardedResolverFactory();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'config.chubbyphp.trustedProxy.trustedProxies must be an array of ips or cidrs, string given'
        );

        $factory($container);
    }

    public function testInvokeWithInvalidHeaders(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => ['10.0.0.0/8'],
                        'headers' => 'X-Real-IP',
                    ],
                ],
            ]),
        ]);

        $factory = new ForwardedResolverFactory();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'config.chubbyphp.trustedProxy.headers must be an array with the keys for, proto and host, string given'
        );

        $factory($container);
    }

    public function testCallStatic(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'default' => [
                            'trustedProxies' => ['192.168.0.0/16'],
                            'headers' => ['for' => 'X-Real-IP'],
                        ],
                    ],
                ],
            ]),
        ]);

        $factory = [ForwardedResolverFactory::class, 'default'];

        $service = $factory($container);

        self::assertInstanceOf(ForwardedResolver::class, $service);

        self::assertEquals(new ForwardedResolver(['192.168.0.0/16'], new ForwardedHeaders('X-Real-IP')), $service);
    }

    public function testCallStaticWithoutTrustedProxies(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'trustedProxy' => [
                        'trustedProxies' => ['10.0.0.0/8'],
                    ],
                ],
            ]),
        ]);

        $factory = [ForwardedResolverFactory::class, 'default'];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'config.chubbyphp.trustedProxy.default.trustedProxies must be an array of ips or cidrs, null given'
        );

        $factory($container);
    }
}
