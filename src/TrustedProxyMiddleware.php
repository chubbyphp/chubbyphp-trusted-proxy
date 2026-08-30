<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Passes the request on with the values of the forwarded resolver as `clientIp`, `scheme` and `host` attributes (the
 * unresolved ones as null, so that nothing set before the middleware survives, no matter if resolved or not).
 *
 * Mind that the middleware only sees the headers and the address of the connection (if the server provides it), so
 * the proxies must set (or strip) all the forwarded headers, as any header they do not touch is supplied by the
 * client.
 */
final class TrustedProxyMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly ForwardedResolverInterface $forwardedResolver) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        foreach ($this->forwardedResolver->resolve($request)->toArray() as $name => $value) {
            $request = $request->withAttribute($name, $value);
        }

        return $handler->handle($request);
    }
}
