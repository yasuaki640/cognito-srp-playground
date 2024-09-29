<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/login', \App\Http\Controllers\LoginFormAction::class);

Route::post('/do-login', \App\Http\Controllers\DoLoginAction::class)->name('do-login');
