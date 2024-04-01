<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;

class UserController extends Controller
{
    protected function userExists($userId)
    {
        return User::where('facebook_id', $userId)->exists();
    }

    public function checkUser(Request $request)
    {
        $userId = $request->input('userId');

        if (is_null($userId)) {
            return response()->json(['error' => 'userId não informado'], 400);
        }

        $exists = $this->userExists($userId);

        return response()->json(['exists' => $exists]);
    }
}
