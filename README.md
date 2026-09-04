# chubbyphp-trusted-proxy

[![CI](https://github.com/chubbyphp/chubbyphp-trusted-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/chubbyphp/chubbyphp-trusted-proxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/chubbyphp/chubbyphp-trusted-proxy/badge.svg?branch=master)](https://coveralls.io/github/chubbyphp/chubbyphp-trusted-proxy?branch=master)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fchubbyphp%2Fchubbyphp-trusted-proxy%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/chubbyphp/chubbyphp-trusted-proxy/master)
[![Latest Stable Version](https://poser.pugx.org/chubbyphp/chubbyphp-trusted-proxy/v)](https://packagist.org/packages/chubbyphp/chubbyphp-trusted-proxy)
[![Total Downloads](https://poser.pugx.org/chubbyphp/chubbyphp-trusted-proxy/downloads)](https://packagist.org/packages/chubbyphp/chubbyphp-trusted-proxy)
[![Monthly Downloads](https://poser.pugx.org/chubbyphp/chubbyphp-trusted-proxy/d/monthly)](https://packagist.org/packages/chubbyphp/chubbyphp-trusted-proxy)

[![bugs](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=bugs)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![code_smells](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=code_smells)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![coverage](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=coverage)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![duplicated_lines_density](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![ncloc](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=ncloc)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![sqale_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![alert_status](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=alert_status)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![reliability_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![security_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=security_rating)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![sqale_index](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=sqale_index)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)
[![vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-trusted-proxy&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-trusted-proxy)

## Description

A trusted proxy middleware for PSR 15: resolves the client ip, scheme and host from the forwarded headers
(`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`) of trusted proxies into request attributes.

## Requirements

 * php: ^8.3
 * [psr/http-message][2]: ^1.1|^2.0
 * [psr/http-server-handler][3]: ^1.0.2
 * [psr/http-server-middleware][4]: ^1.0.2

## Suggest

 * [chubbyphp/chubbyphp-laminas-config-factory][5]: ^1.5.2

## Installation

Through [Composer](http://getcomposer.org) as [chubbyphp/chubbyphp-trusted-proxy][1].

```sh
composer require chubbyphp/chubbyphp-trusted-proxy "^1.1"
```

## Usage

Behind a reverse proxy (nginx, traefik, a load balancer, ...) the server only sees the proxy, the client data arrives
within the forwarded headers, which any client can send as well. The middleware decides which entries of these headers
to trust and passes the request on with the `clientIp`, `scheme` and `host` attributes set, so that every other part
(rate limiting, logging, access control, url generation, ...) reads them from one place instead of parsing headers.

```php
<?php

declare(strict_types=1);

namespace App;

use Chubbyphp\TrustedProxy\ForwardedResolver;
use Chubbyphp\TrustedProxy\TrustedProxyAttributes;
use Chubbyphp\TrustedProxy\TrustedProxyMiddleware;
use Psr\Http\Message\ServerRequestInterface;

$app = ...;

// the ips / cidrs of the proxies: the entries of X-Forwarded-For get walked from the right, the first one not within
// the ranges is the client (robust against a varying number of hops)
$app->add(new TrustedProxyMiddleware(new ForwardedResolver(['10.0.0.0/8', '::1'])));

$handler = static function (ServerRequestInterface $request) {
    // each one ?string: the unresolved ones are null
    $clientIp = $request->getAttribute(TrustedProxyAttributes::CLIENT_IP); // 'clientIp'
    $scheme = $request->getAttribute(TrustedProxyAttributes::SCHEME); // 'scheme'
    $host = $request->getAttribute(TrustedProxyAttributes::HOST); // 'host'

    ...
};
```

Register the middleware **before** any middleware that reads the attributes. Requests without a resolvable client ip
(no `X-Forwarded-For`, only trusted entries, or a first untrusted entry which is not a valid ip like `unknown` or
`ip:port`) get `null` attributes. The middleware always sets all three attributes (the unresolved ones as `null`), so
that nothing set before it survives. A subnet matching every ip (`0.0.0.0/0`, `::/0`) gets rejected, as it would trust
every entry and never resolve anything, an empty list as well, as it would trust no entry and resolve the nearest proxy
as client ip, the entries get trimmed. Ipv4 mapped ipv6 addresses (`::ffff:10.0.0.1`) match ipv4 subnets.

The `clientIp` gets canonicalized (lowercased and compressed, `2001:DB8:0:0::1` as `2001:db8::1`, ipv4 mapped ipv6
addresses as ipv4, `::ffff:203.0.113.1` as `203.0.113.1`), so that the same client always resolves to the same string,
no matter how a hop wrote it (rate limit keys, allowlists, logs). An ipv6 address with a zone id (`fe80::1%eth0`) is
not a valid ip.

The scheme and host get only resolved when a client ip was resolved: the entry at the same position, if the header has
as many entries as the `X-Forwarded-For` header (proxies appending to all of them), the last (the one the nearest proxy
set) otherwise. The scheme gets lowercased and must be `http` or `https`, the host must be a syntactically valid host
(a hostname, an ipv4 or a bracketed ipv6, each with an optional port from 1 to 65535), everything else resolves `null`.

### Security

The trust is anchored at the address of the connection, as `remoteAddress` attribute (set by the server or a middleware
in front, a port gets stripped) or as `REMOTE_ADDR` server param (as set by php-fpm, apache, ...), the attribute wins
over the server param: a connection from outside the trusted ranges counts as the client itself, its address is the
`clientIp` and the headers get ignored. An address which is not a valid ip (junk, a non string) resolves nothing, the
middleware never falls back to the headers. A request without any address of the connection resolves nothing (fail
closed), as the middleware cannot verify that the last hop was a trusted proxy. If the server never provides it (some
runtimes build the request without server params), disable the check explicitly, the server must then not be reachable
except through the proxies:

```php
new ForwardedResolver(['10.0.0.0/8'], requireRemoteAddress: false);
```

Either way, the proxies must set (or strip) all the forwarded headers, as any header they do not touch is supplied by
the client: a proxy passing the client's `X-Forwarded-Proto` / `X-Forwarded-Host` through lets the client choose them,
the middleware cannot tell. The `clientIp` is always a valid ip and the `scheme` always `http` or `https`, but the
`host` is only checked for its syntax: before using it for url generation or redirects, check it against the hosts the
application serves (an allowlist), so that a passed through `X-Forwarded-Host` cannot poison generated urls:

```php
$scheme = $request->getAttribute(TrustedProxyAttributes::SCHEME);
$host = $request->getAttribute(TrustedProxyAttributes::HOST);

if (!in_array($host, ['example.com', 'www.example.com'], true)) {
    return $responseFactory->createResponse(400);
}
```

The RFC 7239 `Forwarded` header (`for=...;proto=...;host=...`) is not supported, only the de-facto `X-Forwarded-*`
headers (or single value ones like `X-Real-IP`, see below): if the proxies send `Forwarded`, configure them to send the
`X-Forwarded-*` headers as well.

### Headers

The second argument replaces the header names (`for` is required, the others are optional, `null` disables them),
useful for a proxy setting a single value header like `X-Real-IP`:

```php
use Chubbyphp\TrustedProxy\ForwardedHeaders;
use Chubbyphp\TrustedProxy\ForwardedResolver;

new ForwardedResolver(['10.0.0.0/8'], new ForwardedHeaders(for: 'X-Real-IP', proto: 'X-Forwarded-Proto', host: null));
```

### Service factories (chubbyphp-laminas-config-factory)

The package ships service factories (built on [chubbyphp-laminas-config-factory][5]) for a PSR 11 container, configured
through `config.chubbyphp.trustedProxy`:

```php
<?php

declare(strict_types=1);

namespace App;

use Chubbyphp\Laminas\Config\Config;
use Chubbyphp\Laminas\Config\ContainerFactory;
use Chubbyphp\TrustedProxy\ForwardedResolverInterface;
use Chubbyphp\TrustedProxy\ServiceFactory\ForwardedResolverFactory;
use Chubbyphp\TrustedProxy\ServiceFactory\TrustedProxyMiddlewareFactory;
use Chubbyphp\TrustedProxy\TrustedProxyMiddleware;

$container = (new ContainerFactory())(new Config([
    'chubbyphp' => [
        'trustedProxy' => [
            'trustedProxies' => ['10.0.0.0/8', '::1'],
            // 'headers' => ['for' => 'X-Forwarded-For', 'proto' => 'X-Forwarded-Proto', 'host' => 'X-Forwarded-Host'],
            // 'requireRemoteAddress' => true,
        ],
    ],
    'dependencies' => [
        'factories' => [
            ForwardedResolverInterface::class => ForwardedResolverFactory::class,
            TrustedProxyMiddleware::class => TrustedProxyMiddlewareFactory::class,
        ],
    ],
]));

$trustedProxyMiddleware = $container->get(TrustedProxyMiddleware::class);
```

The `TrustedProxyMiddlewareFactory` uses the service `ForwardedResolverInterface::class` of the container if
registered, and creates it through the shipped `ForwardedResolverFactory` otherwise. Register it under its name to
replace it or to share it with other services.

#### With names

To serve different parts of an application behind different proxies (a public load balancer, an internal one, ...),
the same factories can be registered multiple times with a name: the config is then read from
`config.chubbyphp.trustedProxy.<name>` and the name gets appended to each service id.

```php
$container = (new ContainerFactory())(new Config([
    'chubbyphp' => [
        'trustedProxy' => [
            'public' => ['trustedProxies' => ['10.0.0.0/8', '::1']],
            'internal' => ['trustedProxies' => ['192.168.0.0/16'], 'headers' => ['for' => 'X-Real-IP', 'host' => null]],
        ],
    ],
    'dependencies' => [
        'factories' => [
            ForwardedResolverInterface::class.'public' => [ForwardedResolverFactory::class, 'public'],
            TrustedProxyMiddleware::class.'public' => [TrustedProxyMiddlewareFactory::class, 'public'],
            ForwardedResolverInterface::class.'internal' => [ForwardedResolverFactory::class, 'internal'],
            TrustedProxyMiddleware::class.'internal' => [TrustedProxyMiddlewareFactory::class, 'internal'],
        ],
    ],
]));

$publicTrustedProxyMiddleware = $container->get(TrustedProxyMiddleware::class.'public');
$internalTrustedProxyMiddleware = $container->get(TrustedProxyMiddleware::class.'internal');
```

## Copyright

2026 Dominik Zogg

[1]: https://packagist.org/packages/chubbyphp/chubbyphp-trusted-proxy

[2]: https://packagist.org/packages/psr/http-message
[3]: https://packagist.org/packages/psr/http-server-handler
[4]: https://packagist.org/packages/psr/http-server-middleware
[5]: https://packagist.org/packages/chubbyphp/chubbyphp-laminas-config-factory
