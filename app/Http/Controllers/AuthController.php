<?php

namespace App\Http\Controllers;

use App\Http\Validators\CMSLoginValidator;
use App\Models\User;
use App\Models\UserSession;
use App\Supports\Message;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth as FacadesJWTAuth;


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
        // $this->middleware('auth:api', ['except' => ['login']]);
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
                'token'       => $token,
                'login_at'    => date("Y-m-d H:i:s", $now),
                'expired_at'  => date("Y-m-d H:i:s", ($now + config('jwt.ttl') * 60)),
                'device_type' => $device_type,
                'device_id'   => array_get($input, 'device_id'),
                'deleted'     => 0,
                'created_at'  => date("Y-m-d H:i:s", $now),
                'created_by'  => Auth::id(),
            ]);
            DB::commit();

            return $this->respondWithToken($token);

        } catch (\Throwable $th) {
            DB::rollBack();
            return response()->json(['errors' => [[$th->getMessage()]]], 500);

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
