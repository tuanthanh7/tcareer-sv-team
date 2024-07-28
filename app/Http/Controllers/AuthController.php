<?php

namespace App\Http\Controllers;

use App\Http\Validators\CMSLoginValidator;
use App\Http\Validators\RegisterValidator;
use App\Models\User;
use App\Models\UserSession;
use App\Supports\Message;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Laravel\Socialite\Facades\Socialite;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth as FacadesJWTAuth;
use Tymon\JWTAuth\JWTAuth;
use App\Providers\RouteServiceProvider;
use Illuminate\Database\QueryException;
use Illuminate\Support\Arr;

class AuthController extends BaseController
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    protected $jwt;
    protected static $_user_type_user;
    protected static $_user_expired_day;
    protected $model;

    public function __construct(FacadesJWTAuth $jwt)
    {
        // $this->middleware('auth:api', ['except' => ['login','refresh','redirectToGoogle']]);
        $this->jwt = $jwt;
        self::$_user_type_user   = "USER";
        self::$_user_expired_day = 365;
        $this->model             = new User();
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // $user = auth()->user();
        // dd($user);
        $input = $request->all();
        (new CMSLoginValidator)->validate($input);

        $credentials = $request->only('phone', 'password');
        // $credentials = request(['phone', 'password']);

        try {
            DB::beginTransaction();
            if (!$token = auth()->attempt($credentials)) {
                return response()->json(['error' => Message::get("users.admin-login-invalid")], 401);
            }

            $user = User::where(['phone' => $input['phone']])->first();
            if(!empty($request->role)){
                if(!($user->role_id == 1)){#admin
                    return $this->responseError("Tài khoản không có quyền truy cập", 401);
                }
            }
            if (empty($user)) {
                return $this->responseError(Message::get("users.admin-login-invalid"), 401);
            }
            if ($user->is_active == "0") {
                return $this->responseError(Message::get("users.user-inactive"), 401);
            }

            // Create refresh token
            $refreshToken = $this->createRefreshToken();

            // Write User Session
            $now = time();
            UserSession::where('user_id', $user->id)->update([
                'deleted'    => 1,
                'updated_at' => date("Y-m-d H:i:s", $now),
                'updated_by' => Auth::id(),
            ]);
            UserSession::where('user_id', $user->id)->delete();

            $device_type = array_get($input, 'device_type', 'UNKNOWN');
            UserSession::insert([
                'user_id'     =>Auth::id(),
                'token'       => $refreshToken,
                'login_at'    => date("Y-m-d H:i:s", $now),
                'expired_at'  => date("Y-m-d H:i:s", ($now + config('jwt.ttl') * 60)),
                'device_type' => $device_type,
                'device_id'   => array_get($input, 'device_id'),
                'deleted'     => 0,
                'created_at'  => date("Y-m-d H:i:s", $now),
                'created_by'  => Auth::id(),
            ]);

            DB::commit();
            return $this->respondWithToken($token,$refreshToken);
            // return response()->json(compact('token','refreshToken'));
            // return $this->respondWithToken($token);

        } catch (\Throwable $th) {
            DB::rollBack();
            return response()->json(['errors' => [[$th->getMessage()]]], 500);

        }
    }

    public function register(Request $request)
    {
        $input                = $request->all();
        (new RegisterValidator)->validate($input);

        try {
            DB::beginTransaction();
            $phone = str_replace(" ", "", $input['phone']);
            $phone = preg_replace('/\D/', '', $phone);
            $names = explode(" ", trim($input['name']));
            $first = $names[0];
            unset($names[0]);
            $last        = !empty($names) ? implode(" ", $names) : null;
            $email       = Arr::get($input, 'email', null);
            $verify_code = mt_rand(100000, 999999);
            $param       = [
                'phone'        => $phone,
                'code'         => $phone,
                'username'     => $phone,
                'first_name'   => $first,
                'last_name'    => $last,
                'short_name'   => $input['name'],
                'full_name'    => $input['name'],
                'email'        => $email,
                'verify_code'  => $verify_code,
                'role_id'      => 2,
                'expired_code' => date('Y-m-d H:i:s', strtotime("+5 minutes")),
                'password'     => password_hash($input['password'], PASSWORD_BCRYPT),
                'genre'        => array_get($input, 'genre', 'O'),
                'address'      => array_get($input, 'address', null),
                'is_active'    => 1,
            ];
            // Create User
            $user = $this->model->create($param);
            // Send Mail
            // if ($email) {
            //     $this->dispatch(new SendMailRegister($email, [
            //         'name'        => $input['name'],
            //         'phone'       => $input['phone'],
            //         'email'       => $input['email'],
            //         'verify_code' => $verify_code,
            //     ]));
            // }
            DB::commit();
            return response()->json(['status' => Message::get("users.register-success", $user->phone)], 200);
        } catch (QueryException $ex) {
            // $response = SERVICE_Error::handle($ex);
            return response()->json(['errors' => [$ex->getMessage()]], 401);
        } catch (\Exception $ex) {
            // $response = SERVICE_Error::handle($ex);
            return response()->json(['errors' => [$ex->getMessage()]], 401);
        }
    }

    // Login Google
    public function redirectToGoogle()
    {
        // return Socialite::driver($provider)->stateless()->redirect();
        return Socialite::driver('google')->stateless()->redirect();
    }

    public function handleGoogleCallback()
    {
        $googleUser = Socialite::driver('google')->stateless()->user();
        dd($googleUser);
        $user = User::where('email', $googleUser->email)->first();
        if(!$user)
        {
            $user = User::create(['name' => $googleUser->name, 'email' => $googleUser->email, 'password' => \Hash::make(rand(100000,999999))]);
        }

        $token = Auth::login($user);
        return $token;
        // return redirect(RouteServiceProvider::HOME);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth('api')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => Message::get("logout-success")]);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        
        // Token cũ sẽ vào blacklisted
        // Làm mới cái token truyền vào
        // return $this->respondWithToken(auth()->refresh());
        $input = request()->all();
        $refreshToken = request()->refresh_token;
        try {
            $refreshTokenCheck = UserSession::where('token',$refreshToken)->first();
            if(empty($refreshTokenCheck)){
                return $this->responseError(Message::get("session.invalid"));
            };
            $now = time();

            // R-Token het han
            if ($refreshTokenCheck->expired_at < $now) {
                return $this->responseError(Message::get("session.expired"));
            }
            $decoded = FacadesJWTAuth::getJWTProvider()->decode($refreshToken);

            // ----
            // -----------------------------
            $user = User::find($decoded['user_id']);
            if (!$user) {
                return $this->responseError("Khong tim thay user");
            }

            // Vo hieu hoa token cũ
            if(!is_null(auth('api')->user())){ // Token chua het han
                auth()->invalidate(true);
            }
            $token = auth('api')->login($user);
            // -----------------------------
            // // Create refresh token
            // $refreshToken = $this->createRefreshToken();

            // // Write User Session
            // UserSession::where('user_id', $user->id)->update([
            //     'deleted'    => 1,
            //     'updated_at' => date("Y-m-d H:i:s", $now),
            //     'updated_by' => Auth::id(),
            // ]);
            // UserSession::where('user_id', $user->id)->delete();

            // $device_type = array_get($input, 'device_type', 'UNKNOWN');
            // UserSession::insert([
            //     'user_id'     =>Auth::id(),
            //     'token'       => $refreshToken,
            //     'login_at'    => date("Y-m-d H:i:s", $now),
            //     'expired_at'  => date("Y-m-d H:i:s", ($now + config('jwt.ttl') * 60)),
            //     'device_type' => $device_type,
            //     'device_id'   => array_get($input, 'device_id'),
            //     'deleted'     => 0,
            //     'created_at'  => date("Y-m-d H:i:s", $now),
            //     'created_by'  => Auth::id(),
            // ]);
            $refreshToken=null;
            return $this->respondWithToken($token,$refreshToken);
        } catch (JWTException $th) {
            return $this->responseError($th->getMessage());
        }
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token, $refreshToken)
    {
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    private function createRefreshToken(){
        $data = [
            'user_id'=>auth('api')->user()->id,
            'random' => rand().time(),
            'exp' => time() + config('jwt.refresh_ttl')
        ];

        $refreshToken = FacadesJWTAuth::getJWTProvider()->encode($data);
        return $refreshToken;
    }
}
