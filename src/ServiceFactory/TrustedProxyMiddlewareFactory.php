<?php

declare(strict_types=1);

namespace Chubbyphp\TrustedProxy\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\TrustedProxy\ForwardedResolverInterface;
use Chubbyphp\TrustedProxy\TrustedProxyMiddleware;
use Psr\Container\ContainerInterface;

final class TrustedProxyMiddlewareFactory extends AbstractFactory
{
    public function __invoke(ContainerInterface $container): TrustedProxyMiddleware
    {
        /** @var ForwardedResolverInterface $forwardedResolver */
        $forwardedResolver = $this->resolveDependency(
            $container,
            ForwardedResolverInterface::class,
            ForwardedResolverFactory::class
        );

        return new TrustedProxyMiddleware($forwardedResolver);
    }
}
