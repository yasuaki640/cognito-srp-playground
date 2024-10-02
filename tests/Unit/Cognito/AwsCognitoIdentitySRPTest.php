<?php

namespace Tests\Unit\Cognito;

use App\Cognito\AwsCognitoIdentitySRP;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

class AwsCognitoIdentitySRPTest extends TestCase
{
    private AwsCognitoIdentitySRP $srpHelper;

    protected function setUp(): void
    {
        $cognitoClient = new CognitoIdentityProviderClient([
            'version' => 'latest',
            'region' => 'ap-northeast-1',
            'credentials' => [
                'key' => 'dummy-key',
                'secret' => 'dummy-secret',
            ],
        ]);

        $this->srpHelper = new AwsCognitoIdentitySRP(
            $cognitoClient,
            'dummy-client-id',
            'dummy-pool-id'
        );
    }

    /**
     * TODO: 書きすぎなテストなので後で消す
     *
     * @throws RandomException
     */
    public function test_calculate_largeA(): void
    {
        $largeA = $this->srpHelper->largeA();
        $this->assertInstanceOf(BigInteger::class, $largeA);
    }

    public function test_fail_if_hashClientSecret_called_without_secret_hash(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('If the user pool has a client secret set, you must pass the `$clientSecret` argument to the constructor');

        $this->srpHelper->cognitoSecretHash('dummy-username');
    }
}
