<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Cognito\AWSCognitoIdentitySRP;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Http\Request;
use Random\RandomException;

class DoLoginAction extends Controller
{
    /**
     * Handle the incoming request.
     *
     * @throws RandomException
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

        $srpClient = new AWSCognitoIdentitySRP(
            $client,
            config('aws.cognito.client_id'),
            config('aws.cognito.user_pool_id')
        );

        $authRes = $srpClient->authenticateUser(
            $request->get('username'),
            $request->get('password')
        );

        return view('top', compact('authRes'));
    }
}
