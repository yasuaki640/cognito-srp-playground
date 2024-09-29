<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Http\Request;

class DoLoginAction extends Controller
{
    /**
     * Handle the incoming request.
     */
    public function __invoke(Request $request)
    {
        $client = new CognitoIdentityProviderClient([
            'version' => 'latest',
            'region' => config('aws.region'),
            'credentials' => [
                'key' => config('aws.key'),
                'secret' => config('aws.secret'),
            ],
        ]);

        $username = $request->get('username');
        $password = $request->get('password');

        $authRes = $client->adminInitiateAuth([
            'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
            'AuthParameters' => [
                'USERNAME' => $username,
                'PASSWORD' => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($username),
            ],
            'ClientId' => config('aws.cognito.client_id'),
            'UserPoolId' => config('aws.cognito.user_pool_id'),
        ]);

        return view('top', compact('authRes'));
    }

    /**
     * Creates the Cognito secret hash
     *
     * @return string
     *
     * @copyright https://www.blackbits.io/blog/laravel-authentication-with-aws-cognito
     */
    protected function cognitoSecretHash(string $username)
    {
        return $this->hash($username.config('aws.cognito.client_id'));
    }

    /**
     * Creates a HMAC from a string
     *
     * @return string
     *
     * @copyright https://www.blackbits.io/blog/laravel-authentication-with-aws-cognito
     */
    protected function hash(string $message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            config('aws.cognito.client_secret'),
            true
        );

        return base64_encode($hash);
    }
}
