<?php

namespace App\Middleware;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Pimcore\Model\DataObject\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpFoundation\JsonResponse;
use function Sabre\Event\Loop\run;

class JWTMiddleware
{
    private $jwtSecret;

    public function __construct(string $jwtSecret)
    {
        $this->jwtSecret = $jwtSecret;
    }

    public function onKernelRequest(RequestEvent $event)
    {
        $request = $event->getRequest();
        $path = $request->getPathInfo();

        if (strpos($path, '/api/user/') !== 0) {
            return;
        }

        if ($request->getMethod() === 'OPTIONS') {
            return;
        }
        \Pimcore\Cache::disable();
        $authHeader = $request->headers->get('Authorization');

        if (empty($authHeader)) {
            $response = $this->createJsonErrorResponse('User không tồn tại trên hệ thống');
            $event->setResponse($response);
            return;
        }
        try {
            $decoded = JWT::decode($authHeader, new Key($this->jwtSecret, 'HS256'));
            $phone = $decoded->sub;
            $user = User::getByPhone($phone, 1);
            if (!empty($user) && $user instanceof User) {
                $request->attributes->set('user', $user);
            } else {
                $response = $this->createJsonErrorResponse('User không tồn tại trên hệ thống');
                $event->setResponse($response);
                return;
            }
        } catch (\Exception $e) {
            $response = $this->createJsonErrorResponse('Invalid JWT token: ' . $e->getMessage());
            $event->setResponse($response);
            return;
        }
    }

    private function createJsonErrorResponse(string $message): JsonResponse
    {
        return new JsonResponse(['error' => $message], JsonResponse::HTTP_FORBIDDEN);
    }
}
