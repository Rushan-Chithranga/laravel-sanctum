<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;
use Throwable;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try
            {
                $validateUser = Validator::make($request->all(),
                [
                    "name" => "required|string",
                    "email" => "required|email|unique:users",
                    "password" => "required|min:6"
                ]);

                if ($validateUser->fails()) {
                    return response()->json([
                        'status' => false,
                        'message' => 'validation failed',
                        'errors' => $validateUser->errors()
                    ],422);
                }

                $user= User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'password' => $request->password
                ]);
                $token = $user->createToken('auth_token', ['*'] , now()->addWeek())->plainTextToken;

                return response()->json([
                    'status' => true,
                    'message' => 'User Created successfully',
                    'user' => $user,
                    'token' => $token
                ],201);
                
            } catch (\Throwable $th){

                return response()->json([
                    'status' => false,
                    'message' => $th->getMessage()
                ],419);
            }


    }
    public function login(Request $request){
        try
        {
            $validateUser = Validator::make($request->all(),
        [
                "email" => "required|email|exists:users",
                "password" => "required|min:6"
            ]);


            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'validation failed',
                    'errors' => $validateUser->errors()
                ],422);
            }
            if (!Auth::attempt($request->only(['email','password']))) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email & password does not match with our record',
                ],401);
            }
            $user = User::where('email',$request->email)->first();

            $token = $user->createToken('auth_token',['*'] , now()->addWeek())->plainTextToken;

            return response()->json([
                'status' => true,
                'message' => 'User Logged successfully',
                'user' => $user,
                'token' => $token
            ],200);

        } catch (\Throwable $th) {

            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ],419);
        }

    }

    public function profile(){
        $userData = auth()->user();
        return response()->json([
            'status' => true,
            'message' => 'Profile Information',
            'data' => $userData,
            'id' => auth()->user()->id
        ],200);
    }

    public function logout(){
        // auth()->user()->tokens()->delete();
        PersonalAccessToken::where('tokenable_id', auth()->id())->delete();
        return response()->json([
            'status' => true,
            'message' => 'UserLogout successfully',
            'data' => [],
        ],200);
    }
}
