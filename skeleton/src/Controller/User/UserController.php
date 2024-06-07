<?php

namespace App\Controller\User;

use App\Service\Auth\JwtService;
use Pimcore\Controller\FrontendController;
use Pimcore\Model\DataObject\User;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Security;
use App\Traits\AuthenticatedUserTrait as AuthTrait;
class UserController extends FrontendController
{
    use AuthTrait;

    private JwtService $jwtService;

    public function __construct(JwtService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    /**
     * @Route("/api/login", name="api_login", methods={"POST"})
     */
    public function login(Request $request): JsonResponse
    {
        $user = $this->authenticate($request);
        if (!empty($user) && $user instanceof User) {
            $payload = ['sub' => $user->getPhone()];
            $token = $this->jwtService->createToken($payload);
            return new JsonResponse(['token' => $token]);
        }

        return new JsonResponse(['message' => 'Invalid credentials'], 401);
    }

    /**
     * @Route("/api/user/list", name="api_secure_endpoint", methods={"GET"})
     */
    public function secureEndpoint(Request $request): JsonResponse
    {
        $jwt = $request->query->all();
        $user = $this->getUserObject($request);
        
        return new JsonResponse(['msg' => 'Hello11']);
    }

    private function authenticate(Request $request)
    {
        $phone = $request->request->get('phone');
        $password = $request->request->get('password');
        $user = User::getByPhone($phone, 1);
        
        if (!empty($user) && $user instanceof User) {
            if (password_verify($password, $user->getPassword())) {
                return $user;
            }
        }
        return false;
    }
}
