<?php

namespace Franklin\OAuth2Client\Tests\Unit\Http\Controllers;

use Carbon\Carbon;
use Franklin\OAuth2Client\Interfaces\TokenRepository;
use Franklin\OAuth2Client\Interfaces\UserRepository;
use Franklin\OAuth2Client\Http\Controllers\OAuth2Controller;
use Franklin\OAuth2Client\Tests\AbstractTestCase;
use Franklin\OAuth2Client\Tests\Unit\UserModel;
use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Hashing\Hasher as Hasher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Mockery;


class OAuthControllerTest extends AbstractTestCase
{
    /**
     * @var \Mockery\Mock|TokenRepository
     */
    private $mockTokenRepository;

    /**
     * @var \Mockery\Mock|UserRepository;
     */
    private $mockUserRepository;

    /**
     * @var \Mockery\Mock|GuzzleClient
     */
    private $mockGuzzleClient;

    /**
     * @var \Mockery\Mock|Config
     */
    private $mockConfig;

    /**
     * @var \Mockery\Mock|Cache
     */
    private $mockCache;

    /**
     * @var \Mockery\Mock|Hasher
     */
    private $mockHasher;

    /**
     * @var \Mockery\Mock|Parser
     */
    private $mockParser;

    /**
     * @var \Mockery\Mock|Token
     */
    private $mockToken;

    /**
     * Test initialisation.
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->mockTokenRepository  = Mockery::mock(TokenRepository::class);
        $this->mockUserRepository   = Mockery::mock(UserRepository::class);
        $this->mockGuzzleClient     = Mockery::mock(GuzzleClient::class);
        $this->mockConfig           = Mockery::mock(Config::class);
        $this->mockCache            = Mockery::mock(Cache::class);
        $this->mockHasher           = Mockery::mock(Hasher::class);
        $this->mockParser           = Mockery::mock(Parser::class);
        $this->mockToken            = Mockery::mock(Token::class);
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
     * Test issuing a token.
     *
     * @return void
     */
    public function testIssueTokenNewUser(): void
    {
        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_redirect_url')->andReturn('http://redirect-url');

        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('get')->once()->with('code')->andReturn('authorization-code');

        $response = $this->generateGuzzleResponse(200, [], ['access_token' => 'jwt-access-token', 'refresh_token' => 'refresh-token', 'expires_in' => '3600']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'redirect_uri'  => 'http://redirect-url',
                'code'          => 'authorization-code',
            ],
        ])->andReturn($response);


        $response = $this->generateGuzzleResponse(200, [], ['uuid' => 'user-uuid', 'username' => 'username']);
        $this->mockGuzzleClient->shouldReceive('get')->once()->with('http://server/api/v1/users/me', [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer jwt-access-token',
            ],
        ])->andReturn($response);

        $user = new UserModel();
        $user->id = 1;
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'user-uuid']]])->andReturn(null);
        $this->mockUserRepository->shouldReceive('create')->once()->with(['uuid' => 'user-uuid', 'username' => 'username'])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('deleteByUserId')->once()->with(1)->andReturn(true);
        $this->mockTokenRepository->shouldReceive('create')->once()->with(['id' => 'token-jti', 'userId' => 1, 'accessTokenHash' => 'hash-string', 'refreshToken' => 'refresh-token', 'accessTokenExpiresAt' => Carbon::now()->addSeconds(3600)])->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->once()->with('jti')->andReturn('token-jti');
        $this->mockParser->shouldReceive('parse')->once()->with('jwt-access-token')->andReturn($this->mockToken);
        $this->mockHasher->shouldReceive('make')->once()->with('jwt-access-token')->andReturn('hash-string');

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);

        $response = $oAuthController->issueToken($mockRequest);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(200, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('tokenType', $responseContent);
        $this->assertEquals('Bearer', $responseContent['tokenType']);
        $this->assertArrayHasKey('accessToken', $responseContent);
        $this->assertEquals('jwt-access-token', $responseContent['accessToken']);
        $this->assertArrayHasKey('expiresIn', $responseContent);
        $this->assertEquals('3600', $responseContent['expiresIn']);
    }

    /**
     * Test issuing a token.
     *
     * @return void
     */
    public function testIssueTokenUserExists(): void
    {
        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_redirect_url')->andReturn('http://redirect-url');

        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('get')->once()->with('code')->andReturn('authorization-code');

        $response = $this->generateGuzzleResponse(200, [], ['access_token' => 'jwt-access-token', 'refresh_token' => 'refresh-token', 'expires_in' => '3600']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'redirect_uri'  => 'http://redirect-url',
                'code'          => 'authorization-code',
            ],
        ])->andReturn($response);


        $response = $this->generateGuzzleResponse(200, [], ['uuid' => 'user-uuid', 'username' => 'username']);
        $this->mockGuzzleClient->shouldReceive('get')->once()->with('http://server/api/v1/users/me', [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer jwt-access-token',
            ],
        ])->andReturn($response);

        $user = new UserModel();
        $user->id = 1;
        $user->username = 'username';
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'user-uuid']]])->andReturn($user);
        $this->mockUserRepository->shouldReceive('update')->once()->with($user, ['username' => 'username'])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('deleteByUserId')->once()->with(1)->andReturn(true);
        $this->mockTokenRepository->shouldReceive('create')->once()->with(['id' => 'token-jti', 'userId' => 1, 'accessTokenHash' => 'hash-string', 'refreshToken' => 'refresh-token', 'accessTokenExpiresAt' => Carbon::now()->addSeconds(3600)])->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->once()->with('jti')->andReturn('token-jti');
        $this->mockParser->shouldReceive('parse')->once()->with('jwt-access-token')->andReturn($this->mockToken);
        $this->mockHasher->shouldReceive('make')->once()->with('jwt-access-token')->andReturn('hash-string');

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);

        $response = $oAuthController->issueToken($mockRequest);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(200, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('tokenType', $responseContent);
        $this->assertEquals('Bearer', $responseContent['tokenType']);
        $this->assertArrayHasKey('accessToken', $responseContent);
        $this->assertEquals('jwt-access-token', $responseContent['accessToken']);
        $this->assertArrayHasKey('expiresIn', $responseContent);
        $this->assertEquals('3600', $responseContent['expiresIn']);
    }

    /**
     * Test issuing a token - error.
     *
     * @return void
     */
    public function testIssueTokenAuthorizationCodeRequestError(): void
    {
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_redirect_url')->andReturn('http://redirect-url');

        
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('get')->once()->with('code')->andReturn('authorization-code');

        $response = $this->generateGuzzleResponse(401, [], ['message' => 'Unauthorized']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'redirect_uri'  => 'http://redirect-url',
                'code'          => 'authorization-code',
            ],
        ])->andReturn($response);

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);

        $response = $oAuthController->issueToken($mockRequest);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('code', $responseContent);
        $this->assertEquals(401, $responseContent['code']);
        $this->assertArrayHasKey('message', $responseContent);
        $this->assertEquals('ID Provider error: Unauthorized', $responseContent['message']);
    }

    /**
     * Test issuing a token - error.
     *
     * @return void
     */
    public function testIssueTokenUsersMeRequestError(): void
    {
        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_redirect_url')->andReturn('http://redirect-url');

        
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('get')->once()->with('code')->andReturn('authorization-code');

        $response = $this->generateGuzzleResponse(200, [], ['access_token' => 'jwt-access-token', 'refresh_token' => 'refresh-token', 'expires_in' => '123456789']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'redirect_uri'  => 'http://redirect-url',
                'code'          => 'authorization-code',
            ],
        ])->andReturn($response);


        $response = $this->generateGuzzleResponse(401, [], ['message' => 'Unauthorized']);
        $this->mockGuzzleClient->shouldReceive('get')->once()->with('http://server/api/v1/users/me', [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer jwt-access-token',
            ],
        ])->andReturn($response);

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);

        $response = $oAuthController->issueToken($mockRequest);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(401, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('code', $responseContent);
        $this->assertEquals(401, $responseContent['code']);
        $this->assertArrayHasKey('message', $responseContent);
        $this->assertEquals('ID Provider error: Unauthorized', $responseContent['message']);
    }

    /**
     * Test issuing a token - user not found.
     *
     * @return void
     */
    public function testIssueTokenUserNotFound(): void
    {
        $this->mockConfig->shouldReceive('get')->twice()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_redirect_url')->andReturn('http://redirect-url');

        
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('get')->once()->with('code')->andReturn('authorization-code');

        $response = $this->generateGuzzleResponse(200, [], ['access_token' => 'jwt-access-token', 'refresh_token' => 'refresh-token', 'expires_in' => '3600']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'redirect_uri'  => 'http://redirect-url',
                'code'          => 'authorization-code',
            ],
        ])->andReturn($response);


        $response = $this->generateGuzzleResponse(200, [], ['uuid' => 'user-uuid', 'username' => 'username']);
        $this->mockGuzzleClient->shouldReceive('get')->once()->with('http://server/api/v1/users/me', [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer jwt-access-token',
            ],
        ])->andReturn($response);

        $user = new UserModel();
        $user->id = 1;
        $this->mockUserRepository->shouldReceive('findBy')->once()->with(['where' => [['uuid', '=', 'user-uuid']]])->andReturn(null);
        $this->mockUserRepository->shouldReceive('create')->once()->with(['uuid' => 'user-uuid', 'username' => 'username'])->andReturn($user);
        $this->mockTokenRepository->shouldReceive('deleteByUserId')->once()->with(1)->andReturn(true);
        $this->mockTokenRepository->shouldReceive('create')->once()->with(['id' => 'token-jti', 'userId' => 1, 'accessTokenHash' => 'hash-string', 'refreshToken' => 'refresh-token', 'accessTokenExpiresAt' => Carbon::now()->addSeconds(3600)])->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->once()->with('jti')->andReturn('token-jti');
        $this->mockParser->shouldReceive('parse')->once()->with('jwt-access-token')->andReturn($this->mockToken);
        $this->mockHasher->shouldReceive('make')->once()->with('jwt-access-token')->andReturn('hash-string');

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);

        $response = $oAuthController->issueToken($mockRequest);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertEquals(200, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('tokenType', $responseContent);
        $this->assertEquals('Bearer', $responseContent['tokenType']);
        $this->assertArrayHasKey('accessToken', $responseContent);
        $this->assertEquals('jwt-access-token', $responseContent['accessToken']);
        $this->assertArrayHasKey('expiresIn', $responseContent);
        $this->assertEquals('3600', $responseContent['expiresIn']);
    }

    /**
     * Test issuing a refresh token.
     *
     * @return void
     */
    public function testRefreshToken(): void
    {
        $refreshToken = new \stdClass();
        $refreshToken->refreshToken = 'refresh-token';

        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with('token-jti')->andReturn($refreshToken);

        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');

        
        $user = new UserModel();
        $user->id = 1;
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('user')->times(1)->withNoArgs()->andReturn($user);
        $mockRequest->shouldReceive('bearerToken')->once()->andReturn('bearer-token');

        $response = $this->generateGuzzleResponse(200, [], ['access_token' => 'jwt-access-token', 'refresh_token' => 'refresh-token', 'expires_in' => '3600']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'refresh_token',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'refresh_token' => $refreshToken->refreshToken,
            ],
        ])->andReturn($response);

        //$this->mockTokenRepository->shouldReceive('deleteByUserId')->once()->with(1)->andReturn(true);
        $this->mockTokenRepository->shouldReceive('create')->once()->with(['id' => 'token-jti', 'userId' => 1, 'accessTokenHash' => 'hash-string', 'refreshToken' => 'refresh-token', 'accessTokenExpiresAt' => Carbon::now()->addSeconds(3600)])->andReturn(true);
        $this->mockHasher->shouldReceive('make')->once()->with('jwt-access-token')->andReturn('hash-string');
        $this->mockToken->shouldReceive('getClaim')->twice()->with('jti')->andReturn('token-jti');
        $this->mockParser->shouldReceive('parse')->once()->with('bearer-token')->andReturn($this->mockToken);
        $this->mockParser->shouldReceive('parse')->once()->with('jwt-access-token')->andReturn($this->mockToken);

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);
        $response = $oAuthController->refreshToken($mockRequest);
        $this->assertEquals(200, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('tokenType', $responseContent);
        $this->assertEquals('Bearer', $responseContent['tokenType']);
        $this->assertArrayHasKey('accessToken', $responseContent);
        $this->assertEquals('jwt-access-token', $responseContent['accessToken']);
        $this->assertArrayHasKey('expiresIn', $responseContent);
        $this->assertEquals(3600, $responseContent['expiresIn']);
    }

    /**
     * Test issuing a refresh token - token doesnt exists.
     *
     * @return void
     */
    public function testTokenTokenNotFound(): void
    {
        $refreshToken = new \stdClass();
        $refreshToken->refreshToken = 'refresh-token';

        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with('token-jti')->andReturn(null);

        $user = new UserModel();
        $user->id = 1;
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('bearerToken')->once()->andReturn('bearer-token');

        $this->mockParser->shouldReceive('parse')->once()->with('bearer-token')->andReturn($this->mockToken);
        $this->mockToken->shouldReceive('getClaim')->once()->with('jti')->andReturn('token-jti');

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);

        $response = $oAuthController->refreshToken($mockRequest);

        $this->assertEquals(401, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('code', $responseContent);
        $this->assertEquals(401, $responseContent['code']);
        $this->assertArrayHasKey('message', $responseContent);
        $this->assertEquals('The refresh token for that user does not exist', $responseContent['message']);
    }

    /**
     * Test issuing a refresh token - oAuth2 server error.
     *
     * @return void
     */
    public function testTokenTokenOAuth2ServerError(): void
    {
        $refreshToken = new \stdClass();
        $refreshToken->refreshToken = 'refresh-token';

        $this->mockTokenRepository->shouldReceive('findByTokenId')->once()->with('token-jti')->andReturn($refreshToken);

        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.oauth2_server_url')->andReturn('http://server');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_id')->andReturn('uuid');
        $this->mockConfig->shouldReceive('get')->once()->with('oauth2client.client_secret')->andReturn('secret');

        
        $user = new UserModel();
        $user->id = 1;
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('bearerToken')->once()->andReturn('bearer-token');

        $this->mockParser->shouldReceive('parse')->once()->with('bearer-token')->andReturn($this->mockToken);
        $this->mockToken->shouldReceive('getClaim')->once()->with('jti')->andReturn('token-jti');

        $response = $this->generateGuzzleResponse(401, [], ['message' => 'Unauthorized']);

        $this->mockGuzzleClient->shouldReceive('post')->with('http://server/oauth/token', [
            'form_params' => [
                'grant_type'    => 'refresh_token',
                'client_id'     => 'uuid',
                'client_secret' => 'secret',
                'refresh_token' => $refreshToken->refreshToken,
            ],
        ])->andReturn($response);

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);
        $response = $oAuthController->refreshToken($mockRequest);
        $this->assertEquals(401, $response->getStatusCode());

        $responseContent = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('code', $responseContent);
        $this->assertEquals(401, $responseContent['code']);
        $this->assertArrayHasKey('message', $responseContent);
        $this->assertEquals('ID Provider error: Unauthorized', $responseContent['message']);
    }

    /**
     * Test logging out.
     *
     * @return void
     */
    public function testLogout(): void
    {
        $user = new UserModel();
        $user->id = 1;
        $mockRequest = Mockery::mock(Request::class);
        $mockRequest->shouldReceive('user')->once()->withNoArgs()->andReturn($user);
        $this->mockTokenRepository->shouldReceive('deleteByUserId')->once()->with(1)->andReturn(true);

        $oAuthController = new OAuth2Controller($this->mockGuzzleClient, $this->mockUserRepository, $this->mockTokenRepository, $this->mockConfig, $this->mockCache, $this->mockHasher, $this->mockParser);
        $response = $oAuthController->logout($mockRequest);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEmpty(json_decode($response->getContent(), true));
    }
}
