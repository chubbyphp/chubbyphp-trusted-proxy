<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Unit;

use Chubbyphp\TrustedProxy\TrustedProxyAttributes;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Chubbyphp\TrustedProxy\TrustedProxyAttributes
 *
 * @internal
 */
final class TrustedProxyAttributesTest extends TestCase
{
    public function testDefaults(): void
    {
        $attributes = new TrustedProxyAttributes();

        self::assertNull($attributes->clientIp);
        self::assertNull($attributes->scheme);
        self::assertNull($attributes->host);
        self::assertSame(['clientIp' => null, 'scheme' => null, 'host' => null], $attributes->toArray());
    }

    public function testToArray(): void
    {
        $attributes = new TrustedProxyAttributes('203.0.113.1', 'https', 'example.com');

        self::assertSame('203.0.113.1', $attributes->clientIp);
        self::assertSame('https', $attributes->scheme);
        self::assertSame('example.com', $attributes->host);
        self::assertSame(
            ['clientIp' => '203.0.113.1', 'scheme' => 'https', 'host' => 'example.com'],
            $attributes->toArray()
        );
    }
}
