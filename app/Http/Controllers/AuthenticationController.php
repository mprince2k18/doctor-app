<?php

namespace App\Http\Controllers;

use App\Helpers\ValidationHelper;
use App\Http\Controllers\BaseApiController;
use App\Http\HttpCode;
use App\Models\User;
use Illuminate\Contracts\Support\Renderable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Repositories\UserRepository;
use RuntimeException;

final class AuthenticationController extends BaseApiController
{

    public function register(Request $request) 
    {
        return "ok";
        return $request;
        $user = User::where('email', $request->email)->first();

        $message  = new User();
        if (!$user) {
            $user = new User();
            $user->email = $request->email;
            $user->password = Hash::make($request->password);
            $user->role = $request->role;
            if($user->save()){
                $message->result = true;
                $message->message = 'Register Successfully Done';
                $message->user_id = $user->id;
                return response($message,200);
            }
        }
        $message->result = false;
        $message->message = 'Email Already Exist';
        return response()->json(['message'=>$message,'status'=>200]);
    }

    public function login(Request $request)
    {
        $message = new User();
        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            $message->result = false;
            $message->message = 'The provided credentials are incorrect.';
        } else {
            $message->result = true;
            $message->name = $user->name ?? 'username';
            $message->id = $user->id;
            $message->email = $user->email;
            $message->role = $user->role;
            $message->token = $user->createToken(env('APP_TOKEN'))->accessToken;
        }
        return response()->json(['message'=>$message,'status'=>200]);
    }

    public function logout(Request $request){
        $result = $request->user()->currentAccessToken()->delete(); //or Auth::user()
        return $result;
    }


}
