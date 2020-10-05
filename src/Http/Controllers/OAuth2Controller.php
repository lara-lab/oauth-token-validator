<?php

namespace AB\OAuthTokenValidator\Http\Controllers;

use AB\OAuthTokenValidator\Contracts\TokenRepositoryContract;
use AB\OAuthTokenValidator\Contracts\UserRepositoryContract;
use AmineAbri\BaseRepository\Exceptions\ModelNotCreatedException;
use AmineAbri\BaseRepository\Exceptions\ModelNotUpdatedException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Parser;

class OAuth2Controller extends BaseController
{
    /**
     * @var Client
     */
    protected $guzzleClient;

    /**
     * @var UserRepositoryContract
     */
    protected $userRepository;

    /**
     * @var TokenRepositoryContract
     */
    protected $tokenRepository;

    /**
     * @var Config
     */
    protected $config;

    /**
     * @var Cache
     */
    protected $cache;

    /**
     * @var Hasher
     */
    protected $hasher;

    /**
     * @var Parser
     */
    protected $parser;

    /**
     * OAuth2Controller constructor.
     *
     * @param Client                    $guzzleClient
     * @param UserRepositoryContract    $userRepository
     * @param TokenRepositoryContract   $tokenRepository
     * @param Config                    $config
     * @param Cache                     $cache
     * @param Hasher                    $hasher
     * @param Parser                    $parser
     *
     * @return void
     */
    public function __construct(
        Client $guzzleClient,
        UserRepositoryContract $userRepository,
        TokenRepositoryContract $tokenRepository,
        Config $config,
        Cache $cache,
        Hasher $hasher,
        Parser $parser
    ) {
        $this->guzzleClient     = $guzzleClient;
        $this->userRepository   = $userRepository;
        $this->tokenRepository  = $tokenRepository;
        $this->config           = $config;
        $this->cache            = $cache;
        $this->hasher           = $hasher;
        $this->parser           = $parser;
    }

    /**
     * Send an issue token request to the IDProvider.
     *
     * @param Request $request
     *
     * @return JsonResponse
     * @throws ModelNotCreatedException
     * @throws ModelNotUpdatedException
     * @throws GuzzleException
     */
    public function issueToken(Request $request): JsonResponse
    {
        $response = $this->guzzleClient->post($this->config->get('oauth-token-validator.oauth2_server_url') . '/oauth/token', [
            'form_params' => [
                'grant_type'    => 'authorization_code',
                'client_id'     => $this->config->get('oauth-token-validator.client_id'),
                'client_secret' => $this->config->get('oauth-token-validator.client_secret'),
                'redirect_uri'  => $this->config->get('oauth-token-validator.client_redirect_url'),
                'code'          => $request->get('code'),
            ],
        ]);

        $tokenResponseData = json_decode((string) $response->getBody());

        if ($response->getStatusCode() !== 200) {
            return new JsonResponse([
                'code' => $response->getStatusCode(),
                'message' => 'ID Provider error: ' .  $tokenResponseData->message
            ], $response->getStatusCode());
        }

        // Pull the user data from the IDProvider server (oAuth2)
        $response = $this->guzzleClient->get(
            $this->config->get('oauth-token-validator.oauth2_server_url') . '/api/v1/users/me',
            [
                'headers' => [
                    'Accept'        => 'application/json',
                    'Authorization' => 'Bearer '. $tokenResponseData->access_token,
                ],
            ]
        );

        $userResponseData = json_decode((string) $response->getBody());

        if ($response->getStatusCode() !== 200) {
            return new JsonResponse([
                'code'      => $response->getStatusCode(),
                'message'   => 'ID Provider error: ' .  $userResponseData->message
            ], $response->getStatusCode());
        }

        // Check if the user exists in the app database. If not, it needs to be created.
        $user = $this->userRepository->findBy(['where' => [['uuid', '=', $userResponseData->uuid]]]);

        if ($user === null) {
            $user = $this->userRepository->create([
                'uuid'      => $userResponseData->uuid,
                'username'  => $userResponseData->username
            ]);
        } else {
            // Update the user's username
            $this->userRepository->update($user, ['username' => $userResponseData->username]);
        }

        // Remove all previous tokens
        $this->tokenRepository->deleteByUserId($user->id);

        // The token id in the database should be the JTI claim value form the actual token
        $token = $this->parser->parse($tokenResponseData->access_token);

        // Store the refresh token in the DB
        $this->tokenRepository->create([
            'id'                    => $token->getClaim('jti'),
            'userId'                => $user->id,
            'accessTokenHash'       => $this->hasher->make($tokenResponseData->access_token),
            'refreshToken'          => $tokenResponseData->refresh_token,
            'accessTokenExpiresAt'  => Carbon::now()->addSeconds($tokenResponseData->expires_in)
        ]);

        // Return only the access token
        return new JsonResponse([
            'tokenType'     => 'Bearer',
            'accessToken'   => $tokenResponseData->access_token,
            'expiresIn'     => $tokenResponseData->expires_in
        ], 200);
    }

    /**
     * Send a refresh token request to the IDProvider.
     *
     * @param Request $request
     *
     * @return JsonResponse
     * @throws GuzzleException
     */
    public function refreshToken(Request $request): JsonResponse
    {
        // Get the refresh token for the current user
        // (the logic of 'logging' the user happens in the ValidateTokenMiddleware)
        // Find the entry in the DB that MATCHES the currently sent access token
        $token = $this->parser->parse($request->bearerToken());
        $refreshTokenRow = $this->tokenRepository->findByTokenId($token->getClaim('jti'));

        if ($refreshTokenRow === null) {
            return new JsonResponse([
                'code' => 401,
                'message' => 'The refresh token for that user does not exist'
            ], 401);
        }

        // Send a rquest to the ID Provider to obtain a new set of tokens
        $response = $this->guzzleClient->post(
            $this->config->get('oauth-token-validator.oauth2_server_url') . '/oauth/token',
            [
                'form_params' => [
                    'grant_type'    => 'refresh_token',
                    'refresh_token' => $refreshTokenRow->refreshToken,
                    'client_id'     => $this->config->get('oauth-token-validator.client_id'),
                    'client_secret' => $this->config->get('oauth-token-validator.client_secret'),
                ],
            ]
        );

        $tokenResponseData = json_decode((string) $response->getBody());

        if ($response->getStatusCode() !== 200) {
            return new JsonResponse([
                'code' => $response->getStatusCode(),
                'message' => 'ID Provider error: ' . $tokenResponseData->message
            ], $response->getStatusCode());
        }

        // Remove all previous tokens
        // Temporarily comment out this line based on:
        // @see https://jira.nccgroup.com/jira/browse/FRAN-1070
        // Instead of being deleting here, they'll naturally expire and be removed by the cleaning job.
        // This might be questioned by pentesters.
        //$this->tokenRepository->deleteByUserId($request->user()->id);

        // The token id in the database should be the JTI claim value form the actual token
        $token = $this->parser->parse($tokenResponseData->access_token);

        // Store the refresh token in the DB
        $this->tokenRepository->create([
            'id'                    => $token->getClaim('jti'),
            'userId'                => $request->user()->id,
            'accessTokenHash'       => $this->hasher->make($tokenResponseData->access_token),
            'refreshToken'          => $tokenResponseData->refresh_token,
            'accessTokenExpiresAt'  => Carbon::now()->addSeconds($tokenResponseData->expires_in)
        ]);

        // Return only the access token
        return new JsonResponse([
            'tokenType' => 'Bearer',
            'accessToken' => $tokenResponseData->access_token,
            'expiresIn' => $tokenResponseData->expires_in
        ], 200);
    }

    /**
     * Perform the logout operation.
     *
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function logout(Request $request): JsonResponse
    {
        // The logout operation is really simple, it removes all tokens belonging to the user which means
        // that it won't be possible to use the current access token anymore or refresh it by using the refresh token.
        $this->tokenRepository->deleteByUserId($request->user()->id);

        return new JsonResponse(null, 200);
    }
}