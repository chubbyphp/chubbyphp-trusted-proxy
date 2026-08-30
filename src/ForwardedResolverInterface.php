<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Resolves the client data of a request out of the forwarded headers, every value not resolvable is null.
 */
interface ForwardedResolverInterface
{
    public function resolve(ServerRequestInterface $request): TrustedProxyAttributes;
}
