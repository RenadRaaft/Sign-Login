<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Contracts\JWTSubject;
// use Tymon\JWTAuth\Contracts\JWTAuth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;


class UsersController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|max:12|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json(['errors'=>$validator->errors()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(['message'=>'User Registered successfully',
         'user'=>$user,
         'token'=>$token], 
         201);
    }
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|max:12|min:6',
        ]);
        $user = User::where('email', $request->email)->first();

        if(!$user)
        {
          return response()->json(['error'=>'invalid Email'],401);  
        }
        elseif(!Hash::check($request->password, $user->password))
        {
            return response()->json(['error'=>'invalid Password'],401);
        }

        $token = JWTAuth::fromUser($user);

        return response()->json(['message'=>'Login successfully',
         'user'=>$user->makeHidden(['password']),
         'token'=>$token], 
         201);
    }
    public function dashboard(Request $request)
    {
       try{
        $user = JWTAuth::parseToken()->authenticate();
       }
       catch(\Tymon\JWTAuth\Exceptions\TokenInvalidException $e){
        return response()->json(['error'=>'Token invalid'],401);
       } 
       catch(\Tymon\JWTAuth\Exceptions\TokenExpiredException $e){
        return response()->json(['error'=>'Token is Expired'],401);
       } 

        return response()->json(['message'=>'Login successfully',
         'user'=>$user,
         'message'=>'welcome to your dashboard']);
    }
    public function logout(Request $request)
    {
       try{
        $token = JWTAuth::getToken();
        if(!$token)
        {
            return response()->json(['error'=>'Token not provided'],401);
        }

        JWTAuth::invalidate($token);
        return response()->json(['message'=>'User logged out successfully']);
       }
       catch(\Tymon\JWTAuth\Exceptions\JWTException $e){
        return response()->json(['error'=>'Failed to logout'],401);
       } 

        
    }
}
