<?php

namespace App\Service\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtService
{
    private string $secretKey;

    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    public function createToken(array $payload): string
    {
        $issuedAt = time();
        $expirationTime = $issuedAt + 3600;
        $payload['iat'] = $issuedAt;
        $payload['exp'] = $expirationTime;

        return JWT::encode($payload, $this->secretKey, 'HS256');
    }

    public function validateToken(string $token): object
    {
        try {
            return JWT::decode($token, new Key($this->secretKey, 'HS256'));
        } catch (\Exception $e) {
            throw new \Exception('Token không hợp lệ hoặc đã hết hạn');
        }
    }
}
