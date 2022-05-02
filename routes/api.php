<?php

use App\Http\Controllers\AuthenticationController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AppController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

Route::get('/fuck',function(){
return 'fuck';
});

Route::post('/login', [AuthenticationController::class, 'login']);
Route::post('/register', [AuthenticationController::class, 'register']);
Route::post('/reset-pass', [AuthenticationController::class, 'resetPassword']); //no
Route::group(['middleware' => 'auth:api'], static function () {
    Route::get('/userinfo', [UserController::class, 'getInfo']);
    Route::put('/editself', [UserController::class, 'editSelf']);
    Route::put("/edituser", [UserController::class, 'editUser']);
    Route::put("/changepassword", [UserController::class, 'changePassword']);
    Route::put('/change-email', [UserController::class, 'changeEmailSelf']);
    Route::delete('/deleteuser', [UserController::class, 'destroyUser']);
    Route::get('/users-list', [UserController::class, 'listUsers']);
});

Route::get('/all-doctors', [AppController::class, 'all_doctors']);
Route::get('/doctor/profile/{user_id}', [AppController::class, 'doctors_profile']);
Route::post('/doctor/profile/update/{user_id}', [AppController::class, 'doctors_profile_update']);
Route::get('/all-patient', [AppController::class, 'all_patient']);
Route::post('/make-appointment', [AppController::class, 'make_appointment']);
Route::put('/accept-appointment/{appointment_id}', [AppController::class, 'accept_appointment']);
Route::get('/appointment-list', [AppController::class, 'appointment_list']);
Route::get('/appointment-list-doctor', [AppController::class, 'appointment_list_doctor']);
Route::get('/appointment-list-patient', [AppController::class, 'appointment_list_patient']);
Route::get('/appointment-list-patient-doctor', [AppController::class, 'appointment_list_patient_doctor']);
Route::post('/give-prescription', [AppController::class, 'give_prescription']);
Route::get('/prescription-list', [AppController::class, 'prescription_list']);


