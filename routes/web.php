<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::post( "/register", [AuthController::class, "register"])->name("register");
Route::post( "/login", [AuthController::class, "login"])->name("login");
