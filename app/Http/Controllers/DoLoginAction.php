<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Cognito\AwsCognitoIdentitySRP;
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

        $srpClient = new AwsCognitoIdentitySRP(
            $client,
            config('aws.cognito.client_id'),
            config('aws.cognito.user_pool_id')
        );

        $username = $request->get('username');

        $result = $client->adminInitiateAuth([
            'AuthFlow' => 'USER_SRP_AUTH',
            'ClientId' => config('aws.cognito.client_id'),
            'UserPoolId' => config('aws.cognito.user_pool_id'),
            'AuthParameters' => [
                'USERNAME' => $username,
                'SRP_A' => $srpClient->largeA()->toHex(),
                'SECRET_HASH' => $srpClient->cognitoSecretHash($username),
            ],
        ]);

        $password = $request->get('password');
        $authRes = $client->adminRespondToAuthChallenge([
            'ChallengeName' => 'PASSWORD_VERIFIER',
            'UserPoolId' => config('aws.cognito.user_pool_id'),
            'ClientId' => config('aws.cognito.client_id'),
            'ChallengeResponses' => $srpClient->processChallenge($result, $username, $password),
        ]);

        return view('top', compact('authRes'));
    }
}
