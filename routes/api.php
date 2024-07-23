<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');


Route::post( "/register", [AuthController::class, "register"])->name("register");
Route::post( "/login", [AuthController::class, "login"])->name("login");

Route::group([
    'middleware' => ['auth:sanctum']
], function(){
    Route::get( "/profile", [AuthController::class, "profile"])->name("profile");
    Route::get( "/logout", [AuthController::class, "logout"])->name("logout");
});
