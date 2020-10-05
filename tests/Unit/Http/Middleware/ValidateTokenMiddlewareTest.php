<?php

namespace Franklin\OAuth2Client\Tests\Unit\Middleware;

use CoderCat\JWKToPEM\JWKConverter;
use Franklin\OAuth2Client\Interfaces\UserRepository;
use Franklin\OAuth2Client\Interfaces\TokenRepository;
use Franklin\OAuth2Client\Exceptions\InvalidTokenException;
use Franklin\OAuth2Client\Http\Middleware\ValidateTokenMiddleware;
use Franklin\OAuth2Client\Models\OAuthTokenModel;
use Franklin\OAuth2Client\Tests\AbstractTestCase;
use Franklin\OAuth2Client\Tests\Unit\UserModel;
use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Auth\AuthManager as Auth;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Parser;
use Mockery;


class ValidateTokenMiddlewareTest extends AbstractTestCase
{
    /**
     * @var Parser
     */
    private $mockParser;

    /**
     * @var JWKConverter
     */
    private $mockJWKConverter;

    /**
     * @var GuzzleClient
     */
    private $mockGuzzleClient;

    /**
     * @var UserRepository
     */
    private $mockUserRepository;

    /**
     * @var TokenRepository;
     */
    private $mockTokenRepository;

    /**
     * @var Config
     */
    private $mockConfig;

    /**
     * @var Cache
     */
    private $mockCache;

    /**
     * @var Auth
     */
    private $mockAuth;

    /**
     * @var Request
     */
    private $mockRequest;

    /**
     * @var array
     */
    private $JWKSResponse;

    /**
     * @var Hasher
     */
    private $mockHasher;

    /**
     * Test initialisation.
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->mockParser           = Mockery::mock(Parser::class);
        $this->mockJWKConverter     = Mockery::mock(JWKConverter::class);
        $this->mockGuzzleClient     = Mockery::mock(GuzzleClient::class);
        $this->mockUserRepository   = Mockery::mock(UserRepository::class);
        $this->mockTokenRepository  = Mockery::mock(TokenRepository::class);
        $this->mockConfig           = Mockery::mock(Config::class);
        $this->mockCache            = Mockery::mock(Cache::class);
        $this->mockAuth             = Mockery::mock(Auth::class);
        $this->mockRequest          = Mockery::mock(Request::class);
        $this->mockHasher           = Mockery::mock(Hasher::class);

        // This the JWKS representation of the public key from the tests directory
        $this->JWKSResponse = [
            'keys' => [
                [
                    'kty'   => 'RSA',
                    'n'     => '4uO3ALiVlmgRkj9iHZdgKVvznJtBqOvBK32zmsHOR59hZmRCdrlGXvteGvpk8bgw1cEczWjKRgRuLQ0RjcrOH2eO1XCzna9cGRhbaR1pbtXADrk-qNkTWn9RdgTI5N3pPY4F2lWwIwzUjk5MjoSz-DPcrxk7kVICQjUqb3quZDHdZa0aJqr8I51hMHNiyWbamCfCS3K1NrK8demG7gIoNyMIfbyAEv0auteNhjFgImQjLdqziaW2ZtgN6cjGPp-YIAwo1RQUczwf0dOVLMEUJ5NoOU6OAJH2pbwtMOzrunkh0zlu1EpKcFnEiLXZdk1bR9wsbXCk-vDb_1lhbBBpXKiOQCQFwss4EYICgRA_L-DF4VeXKN_Qsv2xhIrPPXSPgdUF9l1aAU4mvMaLxR8c93GCxjx8r8yq6HoPb-W1OPqPXFJq-2PrmCWbuaE0iPTS2LFIky06c-xgIijOdA0LTiKtwULd4fsYxt0i4lVak0s8lx8tfNLp6n1yihITUORgkCGmZspkgWDYmH5b2lgVvWT_sotsH3iqFt9HYX_7fKjmGNIBFXFolKExfl2W4IUlyy97sb3urJ0b9dbxyHaUhTmdZtpnZkkjehouWteOcnzjRnsLn0TBATcsJQ4ST3awwcjNml146dOJzAeui6hGHlY1rUqQ9WWXCy44Q1EPTTs',
                    'e'     => 'AQAB',
                    'use'   => 'sig'
                ]
            ]
        ];
    }

    /**
     * Actions to perform after each test.
     *
     * @return void
     */
    public function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    /**
     * Test passing a valid token trough all checks.
     *
     * @return void
     */
    public function testHandle(): void
    {
        $validToken = $this->generateExampleToken();
        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn(env('OAUTH2_CLIENT_ID'));
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);

        $this->mockAuth->shouldReceive('login')->once()->with($user)->andReturn(true);
        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with($validToken->getClaim('jti'))->andReturn(new OAuthTokenModel());
        $this->mockHasher->shouldReceive('check')->once()->andReturn(true);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn($user);

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);

        $returnValue = $validateTokenMiddleware->handle($this->mockRequest, function() { return 'foo';});

        $this->assertEquals('foo', $returnValue);
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenNotPresent(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token is not present.');

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn(null);

        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenInvalidFormat(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token has invalid format.');

        $validToken = $this->generateExampleToken();

        $this->mockParser->shouldReceive('parse')->once()->with($validToken)->andThrow(new \Exception());

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn($validToken);


        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenMissingClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token does not have the required sub claim.');

        $invalidToken = $this->generateMissingSubClaimToken();
        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$invalidToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$invalidToken)->andReturn($invalidToken);

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenInvalidSubClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The sub claim is invalid.');

        $validToken = $this->generateExampleToken();
        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn(null);

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $validateTokenMiddleware->handle($this->mockRequest, function() { return 'foo';});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenRevokedNoTokenFound(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token has been revoked or does not exist anymore.');

        $validToken = $this->generateExampleToken();
        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with($validToken->getClaim('jti'))->andReturn(null);

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenRevokedNoHashMatched(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token has been revoked or does not exist anymore.');

        $validToken = $this->generateExampleToken();
        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with($validToken->getClaim('jti'))->andReturn(new OAuthTokenModel());
        $this->mockHasher->shouldReceive('check')->once()->andReturn(false);

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);

        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenExpired(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token has already expired.');

        $validToken = $this->generateExampleToken(['exp' => Carbon::now()->subDay()->timestamp]);

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with($validToken->getClaim('jti'))->andReturn(new OAuthTokenModel());
        $this->mockHasher->shouldReceive('check')->once()->andReturn(true);

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenInvalidAudClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token aud claim doesnt match the required audience.');

        $validToken = $this->generateExampleToken(['aud' => 'wrong-audience']);

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with($validToken->getClaim('jti'))->andReturn(new OAuthTokenModel());
        $this->mockHasher->shouldReceive('check')->once()->andReturn(true);
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn(env('OAUTH2_CLIENT_ID'));

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenInvalidIssClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token iss claim doesnt match the required issuer.');

        $validToken = $this->generateExampleToken();

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'uuid']]])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with($validToken->getClaim('jti'))->andReturn(new OAuthTokenModel());
        $this->mockHasher->shouldReceive('check')->once()->andReturn(true);
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn(env('OAUTH2_CLIENT_ID'));
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn('invalid-oauth2-server');

        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleInvalidJWKSEndpoint(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('Access token could not be verified as the JWKS endpoint has returned an error.');

        $validToken = $this->generateExampleToken();

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);

        $response = $this->generateGuzzleResponse(401, [], ['message' => 'Unauthorized']);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleEmptyJWKSPublicKey(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('Access token could not be verified as the signature public key cannot be found in the JWKS set.');

        $validToken = $this->generateExampleToken();

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);

        $response = $this->generateGuzzleResponse(200, [], ['no-keys-object' => 'bar']);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleWrongJWKSSignature(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('Access token could not be verified as the signature public key is not available.');

        $validToken = $this->generateExampleToken();

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);

        $response = $this->generateGuzzleResponse(200, [], [
            'keys' => [
                [
                    'kty'   => 'RSA',
                    'n'     => '4uO3ALiVlmgRkj9iHZdgKVvznJtBqOvBK32zmsHOR59hZmRCdrlGXvteGvpk8bgw1cEczWjKRgRuLQ0RjcrOH2eO1XCzna9cGRhbaR1pbtXADrk-qNkTWn9RdgTI5N3pPY4F2lWwIwzUjk5MjoSz-DPcrxk7kVICQjUqb3quZDHdZa0aJqr8I51hMHNiyWbamCfCS3K1NrK8demG7gIoNyMIfbyAEv0auteNhjFgImQjLdqziaW2ZtgN6cjGPp-YIAwo1RQUczwf0dOVLMEUJ5NoOU6OAJH2pbwtMOzrunkh0zlu1EpKcFnEiLXZdk1bR9wsbXCk-vDb_1lhbBBpXKiOQCQFwss4EYICgRA_L-DF4VeXKN_Qsv2xhIrPPXSPgdUF9l1aAU4mvMaLxR8c93GCxjx8r8yq6HoPb-W1OPqPXFJq-2PrmCWbuaE0iPTS2LFIky06c-xgIijOdA0LTiKtwULd4fsYxt0i4lVak0s8lx8tfNLp6n1yihITUORgkCGmZspkgWDYmH5b2lgVvWT_sotsH3iqFt9HYX_7fKjmGNIBFXFolKExfl2W4IUlyy97sb3urJ0b9dbxyHaUhTmdZtpnZkkjehouWteOcnzjRnsLn0TBATcsJQ4ST3awwcjNml146dOJzAeui6hGHlY1rUqQ9WWXCy44Q1EPTTs',
                    'e'     => 'AQAB',
                    'use'   => 'enc' // NO SIG!
                ]
            ]
        ]);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() {});
    }

    /**
     * Test exception.
     *
     * @return void
     */
    public function testHandleTokenInvalidSignature(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionCode(401);
        $this->expectExceptionMessage('The token signature is invalid.');

        $validToken = $this->generateExampleToken();

        $user = new UserModel();
        $user->id = 1;
        $user->uuid = 'uuid';

        $this->mockRequest->shouldReceive('bearerToken')->once()->andReturn((string)$validToken);
        $this->mockParser->shouldReceive('parse')->once()->with((string)$validToken)->andReturn($validToken);
        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.cache_keys.jwks_signature_public_key')->andReturn('cacheprefix');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn(env('OAUTH2_SERVER_URL'));
        $this->mockCache->shouldReceive('get')->once()->withAnyArgs()->andReturn(null);
        $this->mockCache->shouldReceive('put')->once()->withAnyArgs()->andReturn(true);
        $this->mockJWKConverter->shouldReceive('toPEM')->once()->withAnyArgs()->andReturn(file_get_contents(__DIR__ . '/../../../jwt-wrong-sig-public.key'));

        $response = $this->generateGuzzleResponse(200, [], $this->JWKSResponse);
        $this->mockGuzzleClient->shouldReceive('get')->with(env('OAUTH2_SERVER_URL') . '/api/v1/.well-known/jwks.json', [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ])->andReturn($response);

        $validateTokenMiddleware = new ValidateTokenMiddleware($this->mockParser, $this->mockJWKConverter, $this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockAuth, $this->mockHasher);
        $validateTokenMiddleware->handle($this->mockRequest, function() { return 'foo';});
    }
}
