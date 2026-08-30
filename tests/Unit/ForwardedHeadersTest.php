<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\TrustedProxy\Unit;

use Chubbyphp\TrustedProxy\ForwardedHeaders;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Chubbyphp\TrustedProxy\ForwardedHeaders
 *
 * @internal
 */
final class ForwardedHeadersTest extends TestCase
{
    public function testDefaults(): void
    {
        $headers = new ForwardedHeaders();

        self::assertSame('X-Forwarded-For', $headers->for);
        self::assertSame('X-Forwarded-Proto', $headers->proto);
        self::assertSame('X-Forwarded-Host', $headers->host);
    }

    public function testCustom(): void
    {
        $headers = new ForwardedHeaders('X-Real-IP', 'X-Scheme', null);

        self::assertSame('X-Real-IP', $headers->for);
        self::assertSame('X-Scheme', $headers->proto);
        self::assertNull($headers->host);
    }

    /**
     * @param array<string, null|string> $arguments
     */
    #[DataProvider('provideInvalidCases')]
    public function testInvalid(array $arguments, string $message): void
    {
        $create = static fn (): ForwardedHeaders => new ForwardedHeaders(...$arguments);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $create();
    }

    /**
     * @return iterable<string, array{0: array<string, null|string>, 1: string}>
     */
    public static function provideInvalidCases(): iterable
    {
        yield 'empty for' => [['for' => ''], 'headers.for must be a valid header name, "" given'];

        yield 'space in proto' => [['proto' => 'x forwarded'], 'headers.proto must be a valid header name, "x forwarded" given'];

        yield 'colon in host' => [['host' => 'x-host:'], 'headers.host must be a valid header name, "x-host:" given'];

        yield 'newline in for' => [['for' => "x-for\n"], "headers.for must be a valid header name, \"x-for\n\" given"];
    }
}
