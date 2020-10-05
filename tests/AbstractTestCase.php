<?php

namespace Franklin\OAuth2Client\Tests;

use Carbon\Carbon;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    /**
     * Set up
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::now());
    }

    /**
     * Tear down
     *
     * @return void
     */
    public function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The method helps to generate Guzzle responses in an easy way.
     *
     * @param int   $statusCode
     * @param array $headers
     * @param array $body
     *
     * @return Response
     */
    protected function generateGuzzleResponse(int $statusCode, array $headers = [], array $body = []): Response
    {
        $headers['Content-Type'] = 'application/json';

        return new Response($statusCode, $headers, json_encode($body));
    }

    /**
     * Create an example JWT token.
     *
     * @param array $tokenData
     *
     * @return Token
     */
    protected function generateExampleToken(array $tokenData = []): Token
    {
        // Generate a JWT token in the same way as the app would retrieve it from the IDProvider server
        $time = time();
        $signer = new Sha256();
        $privateKey = new Key('file://'. __DIR__ . '/jwt-private.key');

        $token = (new Builder())->issuedBy(env('OAUTH2_SERVER_URL')) // Configures the issuer (iss claim)
                ->permittedFor($tokenData['aud'] ?? env('OAUTH2_CLIENT_ID')) // Configures the audience (aud claim)
                ->identifiedBy('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
                ->issuedAt($time) // Configures the time that the token was issue (iat claim)
                ->canOnlyBeUsedAfter($time + 60) // Configures the time that the token can be used (nbf claim)
                ->expiresAt($tokenData['exp'] ?? $time + 60) // Configures the expiration time of the token (exp claim)
                ->withClaim('sub', $tokenData['sub'] ?? 'uuid'); // Configures a new claim, called "sub";

        if (isset($tokenData['customClaims'])) {
            foreach ($tokenData['customClaims'] as $claimName => $claimValue) {
                $token->withClaim($claimName, $claimValue);
            }
        }

        return $token->getToken($signer,  $privateKey); // Retrieves the generated token
    }

    /**
     * Create an example JWT token with missing required claims.
     *
     * @param array $tokenData
     *
     * @return Token
     */
    protected function generateMissingSubClaimToken(array $tokenData = []): Token
    {
        // Generate a JWT token in the same way as the app would retrieve it from the IDProvider server
        $time = time();
        $signer = new Sha256();
        $privateKey = new Key('file://'. __DIR__ . '/jwt-private.key');

        $token = (new Builder())->issuedBy(env('OAUTH2_SERVER_URL')) // Configures the issuer (iss claim)
            ->permittedFor(env('OAUTH2_CLIENT_ID')) // Configures the audience (aud claim)
            ->identifiedBy('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
            ->issuedAt($time) // Configures the time that the token was issue (iat claim)
            ->canOnlyBeUsedAfter($time + 60) // Configures the time that the token can be used (nbf claim)
            ->expiresAt($tokenData['exp'] ?? $time + 60) // Configures the expiration time of the token (exp claim)
            ->getToken($signer,  $privateKey); // Retrieves the generated token

        return $token;
    }
}
