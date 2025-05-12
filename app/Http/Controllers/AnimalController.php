<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;

class UserController extends Controller
{

    public function list(Request $request)
    {
        $animals =  Animal::where('facebook_id', $userId)->toArray();

        return response()->json(['animals' => $animals]);
    }
}
