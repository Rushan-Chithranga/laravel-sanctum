<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;
use Throwable;



/**
 * @OA\Info(
 *    title=" Santum Application API ",
 *    version="1.0.0",
 * )
 */

class AuthController extends Controller
{
    /**
    * @OA\Post(
    * path="/api/register",
    * operationId="Register",
    * tags={"Register"},
    * summary="User Register",
    * description="User Register here",
    *     @OA\RequestBody(
    *         @OA\JsonContent(),
    *         @OA\MediaType(
    *            mediaType="multipart/form-data",
    *            @OA\Schema(
    *               type="object",
    *               required={"name","email", "password", "password_confirmation"},
    *               @OA\Property(property="name", type="text"),
    *               @OA\Property(property="email", type="text"),
    *               @OA\Property(property="password", type="password"),
    *               @OA\Property(property="password_confirmation", type="password")
    *            ),
    *        ),
    *    ),
    *      @OA\Response(
    *          response=201,
    *          description="Register Successfully",
    *          @OA\JsonContent()
    *       ),
    *      @OA\Response(
    *          response=200,
    *          description="Register Successfully",
    *          @OA\JsonContent()
    *       ),
    *      @OA\Response(
    *          response=422,
    *          description="Unprocessable Entity",
    *          @OA\JsonContent()
    *       ),
    *      @OA\Response(response=400, description="Bad request"),
    *      @OA\Response(response=404, description="Resource Not Found"),
    * )
    */
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

    /**
    * @OA\Post(
    *     path="/api/login",
    *     operationId="Login",
    *     tags={"Login"},
    *     summary="User Login",
    *     description="User Login here",
    *     @OA\RequestBody(
    *         required=true,
    *         @OA\MediaType(
    *            mediaType="multipart/form-data",
    *            @OA\Schema(
    *               type="object",
    *               required={"email", "password"},
    *               @OA\Property(property="email", type="string", example="sanjay@gmail.com"),
    *               @OA\Property(property="password", type="string", example="123456"),
    *            ),
    *        ),
    *        @OA\MediaType(
    *            mediaType="application/json",
    *            @OA\Schema(
    *               type="object",
    *               required={"email", "password"},
    *               @OA\Property(property="email", type="string", example="sanjay@gmail.com"),
    *               @OA\Property(property="password", type="string", example="123456"),
    *            ),
    *        ),
    *    ),
    *    @OA\Response(
    *        response=201,
    *        description="Login Successfully",
    *        @OA\JsonContent()
    *    ),
    *    @OA\Response(
    *        response=200,
    *        description="Login Successfully",
    *        @OA\JsonContent()
    *    ),
    *    @OA\Response(
    *        response=422,
    *        description="Unprocessable Entity",
    *        @OA\JsonContent()
    *    ),
    *    @OA\Response(response=400, description="Bad request"),
    *    @OA\Response(response=404, description="Resource Not Found"),
    * )
    */
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


    /**
    * @OA\Get(
    *     path="/api/profile",
    *     operationId="getProfile",
    *     tags={"Profile"},
    *     summary="Get user profile",
    *     description="Retrieve user profile information.",
    *     security={{"bearerAuth":{}}},
    *     @OA\Parameter(
    *         name="Authorization",
    *         in="header",
    *         description="Authorization Token",
    *         required=true,
    *         @OA\Schema(
    *             type="string",
    *             default="Bearer your_access_token_here"
    *         )
    *     ),
    *     @OA\Response(
    *         response=200,
    *         description="Successful operation",
    *         @OA\JsonContent()
    *     ),
    *     @OA\Response(
    *         response=401,
    *         description="Unauthorized"
    *     )
    * )
    *
    * @OA\SecurityScheme(
    *     securityScheme="bearerAuth",
    *     type="http",
    *     scheme="bearer",
    *     bearerFormat="JWT"
    * )
    */
    public function profile(){
        $userData = auth()->user();
        return response()->json([
            'status' => true,
            'message' => 'Profile Information',
            'data' => $userData,
            'id' => auth()->user()->id
        ],200);
    }

      /**
     * @OA\Delete(
     *     path="/api/logout",
     *     operationId="logout",
     *     tags={"Logout"},
     *     summary="User Logout",
     *     description="Logs out the authenticated user and revokes all their tokens.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="Authorization",
     *         in="header",
     *         description="Authorization Token",
     *         required=true,
     *         @OA\Schema(
     *             type="string",
     *             default="Bearer your_access_token_here"
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="status",
     *                 type="boolean",
     *                 description="Status of the operation."
     *             ),
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 description="Message indicating the result."
     *             )
     *         )
     *     ),
     * )
     */
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
