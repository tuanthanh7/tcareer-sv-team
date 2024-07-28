<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->get('/', function () use ($router) {
    // return $router->app->version();
    // return $router->app->version() . " - OK - API-SERVICE - ON DEVICE: " . get_device() . " - PHP VERSION: " . phpversion();
    return $router->app->version() . " - PHP VERSION: " . phpversion();
});

// $router->group(['middleware' => 'api', 'prefix' => 'auth'], function ($router) {
$router->group(['prefix' => 'auth'], function ($router) {

    $router->post('login', 'AuthController@login');
    $router->post('logout', 'AuthController@logout');
    $router->post('refresh', 'AuthController@refresh');
    $router->post('register', 'AuthController@register');
    $router->post('me', 'AuthController@me');
    $router->get('google/redirect', 'AuthController@redirectToGoogle');
    $router->get('google/callback', 'AuthController@handleGoogleCallback');

});
