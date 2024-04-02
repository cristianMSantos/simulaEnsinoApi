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

        $email = $request->input('data.email');
        $password = $request->input('data.password');

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

        // Obtém o usuário autenticado
        $user = auth()->user();

        return response()->json([
            'token_data' => $this->respondWithToken($token)->original,
            'user' => $user
        ]);
        // return $this->respondWithToken($token);
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

        $linkedAccount = $request->input('linkedAccount');
        $cpf = str_replace(['.', '-'], '', $request->input('registration.cpf'));
        // Verificar se o usuário já existe no banco de dados
        $user = User::where('cpf', $cpf)->first();

        if($user && !$linkedAccount){
            return response()->json(['userPicture' => $user->picture, 'userStatus' => $user->status, 'userEmail' => $user->email, 'message' => 'The User already exists'], 401);
        }

        if($user && $linkedAccount){
            return $this->linkAccount($request);
        }

        // $newUser = new User;
        // $newUser->username = ;
        // $newUser->first_name = ;
        // $newUser->last_name = ;
        // $newUser->name = ;
        // $newUser->cpf = ;
        // // $newUser->password = ;
        // $newUser->email = ;
        // $newUser->facebook_id = ;
        // $newUser->google_id = ;
        // $newUser->picture = ;
        // $newUser->status = ;
        // $newUser->profile_id = ;
        // $newUser->dt_create = ;
        // // $newUser->save()
    }

    public function linkAccount(Request $request){
        // return $request->input('registration.provider');
        $provider = $request->input('registration.provider');
        $userID = $request->input('registration.userID');
        $cpf = str_replace(['.', '-'], '', $request->input('registration.cpf'));
        $credentials = [
            'email' => $request->input('linked.email'),
            'password' => $request->input('linked.password')
        ];

        // Tente fazer login com as credenciais fornecidas
        $loginAttempt = auth()->attempt($credentials);

        date_default_timezone_set('america/sao_paulo');


        if ($loginAttempt && User::where('cpf', $cpf)->exists()) {
            $user = User::where('cpf', $cpf)->first();
    
            try {
                if ($provider === 'facebook') {
                    User::where('cpf', $cpf)->update([
                        'facebook_id' => $userID,
                        'dt_update' => date('Y-m-d H:i', time()),
                    ]);
                }
    
                if ($provider === 'google') {
                    User::where('cpf', $cpf)->update([
                        'google_id' => $userID,
                        'dt_update' => date('Y-m-d H:i', time()),
                    ]);
                }

                 // Obtém o usuário autenticado
                $userAuth = auth()->user();

                return response()->json([
                    'token_data' => $this->respondWithToken($loginAttempt)->original,
                    'user' => $userAuth
                ]);
    
            } catch (\Exception $e) {
                return response()->json([
                    'error' => 'Error linking account. Please try again later.'
                ], 500); 
            }
        }

        return response()->json(['error' => 'Unauthorized', 'message' => 'Unauthorized'], 401);
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
