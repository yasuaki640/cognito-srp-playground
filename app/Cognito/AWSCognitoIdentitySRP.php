<?php

// This class is a ported implementation of https://gist.github.com/jenky/a4465f73adf90206b3e98c3d36a3be4f

declare(strict_types=1);

namespace App\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Result;
use Carbon\Carbon;
use InvalidArgumentException;
use phpseclib3\Math\BigInteger;
use Random\RandomException;
use RuntimeException;

class AWSCognitoIdentitySRP
{
    const N_HEX = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
        'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
        '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'.
        'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
        '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64'.
        'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'.
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B'.
        'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'.
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31'.
        '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

    const G_HEX = '2';

    const INFO_BITS = 'Caldera Derived Key';

    protected BigInteger $N;

    protected BigInteger $g;

    protected BigInteger $k;

    protected ?BigInteger $a;

    protected ?BigInteger $A;

    protected string $clientId;

    protected string $poolId;

    protected CognitoIdentityProviderClient $client;

    /**
     * Create new AWS CognitoIDP instance.
     *
     * @return void
     */
    public function __construct(CognitoIdentityProviderClient $client, string $clientId, string $poolId)
    {
        $this->N = new BigInteger(static::N_HEX, 16);
        $this->g = new BigInteger(static::G_HEX, 16);
        $this->k = new BigInteger($this->hexHash('00'.static::N_HEX.'0'.static::G_HEX), 16);

        $this->a = null;
        $this->A = null;

        $this->client = $client;
        $this->clientId = $clientId;
        $this->poolId = $poolId;
    }

    /**
     * Get random a value.
     *
     * @throws RandomException
     */
    public function smallA(): BigInteger
    {
        if (is_null($this->a)) {
            $this->a = $this->generateRandomSmallA();
        }

        return $this->a;
    }

    /**
     * Get the client's public value A with the generated random number a.
     *
     * @throws RandomException
     */
    public function largeA(): BigInteger
    {
        if (is_null($this->A)) {
            $this->A = $this->calculateA($this->smallA());
        }

        return $this->A;
    }

    /**
     * Generate random bytes as hexadecimal string.
     *
     * @throws RandomException
     */
    public function bytes(int $bytes = 32): BigInteger
    {
        $bytes = bin2hex(random_bytes($bytes));

        return new BigInteger($bytes, 16);
    }

    /**
     * Converts a BigInteger (or hex string) to hex format padded with zeroes for hashing.
     */
    public function padHex(BigInteger|string $longInt): string
    {
        $hashStr = $longInt instanceof BigInteger ? $longInt->toHex() : $longInt;

        if (strlen($hashStr) % 2 === 1) {
            $hashStr = '0'.$hashStr;
        } elseif (str_contains('89ABCDEFabcdef', $hashStr[0] ?? '')) {
            $hashStr = '00'.$hashStr;
        }

        return $hashStr;
    }

    /**
     * Calculate a hash from a hex string.
     */
    public function hexHash(string $value): string
    {
        return $this->hash(hex2bin($value));
    }

    /**
     * Calculate a hash from string.
     */
    public function hash(string $value): string
    {
        $hash = hash('sha256', $value);

        return str_repeat('0', 64 - strlen($hash)).$hash;
    }

    /**
     * Performs modulo between big integers.
     */
    protected function mod(BigInteger $a, BigInteger $b): BigInteger
    {
        return $a->powMod(new BigInteger(1), $b);
    }

    /**
     * Generate a random big integer.
     *
     * @throws RandomException
     */
    public function generateRandomSmallA(): BigInteger
    {
        return $this->mod($this->bytes(128), $this->N);
    }

    /**
     * Calculate the client's public value A = g^a%N.
     *
     *
     * @throws InvalidArgumentException
     */
    public function calculateA(BigInteger $a): BigInteger
    {
        $A = $this->g->powMod($a, $this->N);

        if ($this->mod($a, $this->N)->equals(new BigInteger(0))) {
            throw new InvalidArgumentException('Public key failed A mod N == 0 check.');
        }

        return $A;
    }

    /**
     * Calculate the client's value U which is the hash of A and B.
     */
    public function calculateU(BigInteger $A, BigInteger $B): BigInteger
    {
        $A = $this->padHex($A);
        $B = $this->padHex($B);

        return new BigInteger($this->hexHash($A.$B), 16);
    }

    /**
     * Extract the pool ID from pool name.
     */
    protected function poolId(): ?string
    {
        return explode('_', $this->poolId)[1] ?? null;
    }

    /**
     * Authenticate user with given username and password.
     *
     *
     * @throws RuntimeException|RandomException
     */
    public function authenticateUser(string $username, string $password): Result
    {
        $result = $this->client->adminInitiateAuth([
            'AuthFlow' => 'USER_SRP_AUTH',
            'ClientId' => $this->clientId,
            'UserPoolId' => $this->poolId,
            'AuthParameters' => [
                'USERNAME' => $username,
                'SRP_A' => $this->largeA()->toHex(),
                'SECRET_HASH' => $this->cognitoSecretHash($username),
            ],
        ]);

        if ($result->get('ChallengeName') != 'PASSWORD_VERIFIER') {
            throw new RuntimeException("ChallengeName `{$result->get('ChallengeName')}` is not supported.");
        }

        return $this->client->adminRespondToAuthChallenge([
            'ChallengeName' => 'PASSWORD_VERIFIER',
            'UserPoolId' => $this->poolId,
            'ClientId' => $this->clientId,
            'ChallengeResponses' => $this->processChallenge($result, $username, $password),
        ]);
    }

    /**
     * Generate authentication challenge response params.
     *
     * @throws RandomException
     */
    protected function processChallenge(
        Result $result,
        string $username,
        string $password
    ): array {
        $challengeParameters = $result->get('ChallengeParameters');
        $time = Carbon::now('UTC')->format('D M j H:i:s e Y');
        $secretBlock = base64_decode($challengeParameters['SECRET_BLOCK']);
        $userId = $challengeParameters['USER_ID_FOR_SRP'];

        $hkdf = $this->getPasswordAuthenticationKey(
            $userId,
            $password,
            $challengeParameters['SRP_B'],
            $challengeParameters['SALT']
        );

        $msg = $this->poolId().$userId.$secretBlock.$time;
        $signature = hash_hmac('sha256', $msg, $hkdf, true);

        return [
            'TIMESTAMP' => $time,
            'USERNAME' => $userId,
            'PASSWORD_CLAIM_SECRET_BLOCK' => $challengeParameters['SECRET_BLOCK'],
            'PASSWORD_CLAIM_SIGNATURE' => base64_encode($signature),
            'SECRET_HASH' => $this->cognitoSecretHash($username),
        ];
    }

    /**
     * Calculates the final hkdf based on computed S value, and computed U value and the key.
     *
     *
     * @throws RuntimeException|RandomException
     */
    protected function getPasswordAuthenticationKey(string $username, string $password, string $server, string $salt): string
    {
        $u = $this->calculateU($this->largeA(), $serverB = new BigInteger($server, 16));

        if ($u->equals(new BigInteger(0))) {
            throw new RuntimeException('U cannot be zero.');
        }

        $usernamePassword = sprintf('%s%s:%s', $this->poolId(), $username, $password);
        $usernamePasswordHash = $this->hash($usernamePassword);

        $x = new BigInteger($this->hexHash($this->padHex($salt).$usernamePasswordHash), 16);
        $gModPowXN = $this->g->modPow($x, $this->N);
        $intValue2 = $serverB->subtract($this->k->multiply($gModPowXN));
        $s = $intValue2->modPow($this->smallA()->add($u->multiply($x)), $this->N);

        return $this->computeHkdf(
            hex2bin($this->padHex($s)),
            hex2bin($this->padHex($u))
        );
    }

    /**
     * Standard hkdf algorithm.
     */
    protected function computeHkdf(string $ikm, string $salt): string
    {
        return hash_hkdf('sha256', $ikm, 16, static::INFO_BITS, $salt);
    }

    /**
     * Creates the Cognito secret hash
     *
     *
     * @copyright https://www.blackbits.io/blog/laravel-authentication-with-aws-cognito
     */
    protected function cognitoSecretHash(string $username): string
    {
        return $this->hashClientSecret($username.config('aws.cognito.client_id'));
    }

    /**
     * Creates a HMAC from a string
     *
     *
     * @copyright https://www.blackbits.io/blog/laravel-authentication-with-aws-cognito
     */
    protected function hashClientSecret(string $message): string
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
