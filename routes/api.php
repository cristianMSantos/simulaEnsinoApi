<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use App\Http\Middleware\Authenticate;

Route::get('/test', function () {
    return 'test';
});


Route::middleware([Authenticate::class])->group(function () {
    // Este grupo de rotas é protegido pela middleware Authenticate
    Route::prefix('auth')->group(function () {
        Route::post('login', [AuthController::class, 'login'])->withoutMiddleware([Authenticate::class]);
        Route::post('login-registration', [AuthController::class, 'registration'])->withoutMiddleware([Authenticate::class]);
        Route::post('link-account', [AuthController::class, 'linkAccount'])->withoutMiddleware([Authenticate::class]);
        Route::post('logout', [AuthController::class, 'logout']);
        Route::post('refresh', [AuthController::class, 'refresh']);
        Route::post('me', [AuthController::class, 'me']);
    });
    
    Route::prefix('user')->group(function () {
        Route::post('check-user', [UserController::class, 'checkUser'])->withoutMiddleware([Authenticate::class]);
    });
});


