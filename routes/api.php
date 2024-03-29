<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Middleware\Authenticate;

Route::get('/test', function () {
    return 'test';
});


Route::middleware([Authenticate::class])->prefix('auth')->group(function ($router) {

    Route::post('login', [AuthController::class, 'login'])->withoutMiddleware([Authenticate::class]);;
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('me', [AuthController::class, 'me']);
    
});


