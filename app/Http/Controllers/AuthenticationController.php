<?php

namespace App\Http\Controllers;

use App\Helpers\ValidationHelper;
use App\Http\Controllers\BaseApiController;
use App\Http\HttpCode;
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
    public function login(): JsonResponse
    {
        $data = request()->all();

        try {
            ValidationHelper::validate($data, [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if (Auth::attempt(['email' => $data['email'], 'password' => $data['password']])) {
                $user = UserRepository::currentUser();
                $email = $user->email ?? '';
                $success = [];
                $success['token'] = $user->createToken('passport-api')->accessToken;
                $user->setRememberToken(base64_encode(Hash::make(time() . $email)));
                $success['rememberToken'] = $user->getRememberToken();

                if ($user->save()) {
                    return $this->respond(['success' => $success]);
                }
            }
        } catch (RuntimeException $error) {
            return response()->json(['error' => $error->getMessage()], HttpCode::BAD_REQUEST);
        }

        return $this->respondWithError([__('messages.general-issue')]);
    }

    public function register(): JsonResponse
    {
        $userRepository = new UserRepository();

        $data = request()->all();

        try {
            ValidationHelper::validate($data, [
                'email' => 'required|unique:users|email',
                'password' => 'required',
                'name' => 'required',
                'role' => 'required',
            ]);

            $user = $userRepository->registerUser($data);
            $token = $user->createToken('passport-api')->accessToken;
            $user->setRememberToken(base64_encode(Hash::make(time() . $user->email)));
            if($user->save()) {
                return $this->respond(['token' => $token], __('messages.registration-success'), 201);
            }

        } catch (RuntimeException $error) {
            return $this->respondWithError(ValidationHelper::splitErrors($error->getMessage()));
        }
        return $this->respondWithError([__('messages.general-issue')]);
    }

    public function resetPassword() {
        $data = request()->all();

        try {
            ValidationHelper::validate($data,[
                'email' => 'required|email'
            ]);

            // send an email with a reset password link?

        } catch (RuntimeException $error) {
            return $this->respondWithError(ValidationHelper::splitErrors($error->getMessage()));
        }
        return $this->respondWithError([__('messages.general-issue')]);
    }

}
