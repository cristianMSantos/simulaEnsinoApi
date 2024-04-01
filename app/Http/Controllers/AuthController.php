<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controllers\Middleware;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
     /**
     * Create a new AuthController instance.
     *
     * @return void
     */


    public function __construct()
    {
        // $this->middleware('auth', ['except' => ['login']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {

        $provider = $request->input('data.provider');

        if($provider === 'facebook'){
            return $this->facebookLogin($request);
        }

        $email = $request->input('email');
        $password = $request->input('password');

        // Verifique se o e-mail e a senha foram fornecidos
        if (is_null($email) || is_null($password)) {
            return response()->json(['error' => 'Senha ou Login não informados'], 404);
        }

        $credentials = [
            'email' => $email,
            'password' => $password
        ];

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function facebookLogin(Request $request)
    {

        $userId = $request->input('data.userID');
        // Verificar se o usuário já existe no banco de dados
        $user = User::where('facebook_id', $userId)->first();

        // Gerar token de acesso para o usuário
        $token = auth()->login($user);

        // Retornar o token de acesso
        return $this->respondWithToken($token);
    }

    
    public function registration(Request $request){

        $cpf = str_replace(['.', '-'], '', $request->input('cpf'));
        // Verificar se o usuário já existe no banco de dados
        $user = User::where('cpf', $cpf)->first();

        if($user){
            return response()->json(['message' => 'The User already exists'], 401);
        }
    }


    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
