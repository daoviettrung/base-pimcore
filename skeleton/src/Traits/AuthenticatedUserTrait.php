<?php

namespace App\Traits;

use Symfony\Component\HttpFoundation\Request;

trait AuthenticatedUserTrait
{
    public function getUserObject(Request $request)
    {
        return $request->attributes->get('user');
    }
}