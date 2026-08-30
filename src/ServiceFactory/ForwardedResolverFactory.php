<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\TrustedProxy\ForwardedHeaders;
use Chubbyphp\TrustedProxy\ForwardedResolver;
use Chubbyphp\TrustedProxy\ForwardedResolverInterface;
use Psr\Container\ContainerInterface;

/**
 * Reads `config.chubbyphp.trustedProxy` (or `config.chubbyphp.trustedProxy.<name>` for named factories):
 *  - `trustedProxies`: the ips / cidrs of the proxies
 *  - `headers`: the forwarded header names (`for`, `proto`, `host`), replace the defaults
 *  - `requireRemoteAddress`: resolve nothing if the request carries no address of the connection (default true)
 */
final class ForwardedResolverFactory extends AbstractFactory
{
    private const array HEADER_KEYS = ['for', 'proto', 'host'];

    public function __invoke(ContainerInterface $container): ForwardedResolverInterface
    {
        /** @var array{chubbyphp?: array{trustedProxy?: array<string, mixed>}} $config */
        $config = $container->get('config');

        /** @var array{trustedProxies?: mixed, headers?: mixed, requireRemoteAddress?: mixed} $trustedProxyConfig */
        $trustedProxyConfig = $this->resolveConfig($config['chubbyphp']['trustedProxy'] ?? []);

        $path = 'config.chubbyphp.trustedProxy'.('' === $this->name ? '' : '.'.$this->name);

        $trustedProxies = $trustedProxyConfig['trustedProxies'] ?? null;

        if (!\is_array($trustedProxies)) {
            throw new \InvalidArgumentException(\sprintf(
                '%s.trustedProxies must be an array of ips or cidrs, %s given',
                $path,
                get_debug_type($trustedProxies)
            ));
        }

        $headers = $trustedProxyConfig['headers'] ?? [];

        if (!\is_array($headers)) {
            throw new \InvalidArgumentException(\sprintf(
                '%s.headers must be an array with the keys for, proto and host, %s given',
                $path,
                get_debug_type($headers)
            ));
        }

        foreach ($headers as $key => $name) {
            if (!\in_array($key, self::HEADER_KEYS, true)) {
                throw new \InvalidArgumentException(\sprintf(
                    '%s.headers must be an array with the keys for, proto and host, key "%s" given',
                    $path,
                    $key
                ));
            }

            if (!\is_string($name) && ('for' === $key || null !== $name)) {
                throw new \InvalidArgumentException(\sprintf(
                    '%s.headers.%s must be a %s, %s given',
                    $path,
                    $key,
                    'for' === $key ? 'string' : 'string or null',
                    get_debug_type($name)
                ));
            }
        }

        $requireRemoteAddress = $trustedProxyConfig['requireRemoteAddress'] ?? true;

        if (!\is_bool($requireRemoteAddress)) {
            throw new \InvalidArgumentException(\sprintf(
                '%s.requireRemoteAddress must be a bool, %s given',
                $path,
                get_debug_type($requireRemoteAddress)
            ));
        }

        /** @var list<string> $trustedProxies */

        /** @var array{for?: string, proto?: null|string, host?: null|string} $headers */
        try {
            return new ForwardedResolver($trustedProxies, new ForwardedHeaders(...$headers), $requireRemoteAddress);
        } catch (\InvalidArgumentException $e) {
            // the messages start with the key (`trustedProxies ...`, `headers.for ...`), so the path gets prepended
            throw new \InvalidArgumentException($path.'.'.$e->getMessage(), 0, $e);
        }
    }
}
