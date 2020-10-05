<?php

namespace AB\OAuthTokenValidator\Http\Middleware;

use Closure;
use CoderCat\JWKToPEM\Exception\Base64DecodeException;
use CoderCat\JWKToPEM\Exception\JWKConverterException;
use CoderCat\JWKToPEM\JWKConverter;
use AB\OAuthTokenValidator\Contracts\TokenRepositoryContract;
use AB\OAuthTokenValidator\Contracts\UserRepositoryContract;
use AB\OAuthTokenValidator\Exceptions\InvalidTokenException;
use Exception;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Auth\AuthManager as Auth;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Psr\SimpleCache\InvalidArgumentException;

class ValidateTokenMiddleware
{
    /**
     * @var array
     */
    protected $requiredClaims = ['iss', 'sub', 'aud', 'iat', 'jti', 'exp'];

    /**
     * @var array
     */
    protected $forbiddenClaims = [];

    /**
     * @var Parser
     */
    protected $parser;

    /**
     * @var JWKConverter
     */
    protected $JWKConverter;

    /**
     * @var GuzzleClient
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
     * @var Auth
     */
    protected $auth;

    /**
     * @var Hasher
     */
    protected $hasher;

    /**
     * ValidateTokenMiddleware constructor.
     *
     * @param Parser            $parser
     * @param JWKConverter      $JWKConverter
     * @param GuzzleClient      $guzzleClient
     * @param UserRepositoryContract    $userRepository
     * @param TokenRepositoryContract   $tokenRepository
     * @param Config            $config
     * @param Cache             $cache
     * @param Auth              $auth
     * @param Hasher            $hasher
     *
     * @return void
     */
    public function __construct(
        Parser $parser,
        JWKConverter $JWKConverter,
        GuzzleClient $guzzleClient,
        UserRepositoryContract $userRepository,
        TokenRepositoryContract $tokenRepository,
        Config $config,
        Cache $cache,
        Auth $auth,
        Hasher $hasher
    ) {
        $this->parser           = $parser;
        $this->JWKConverter     = $JWKConverter;
        $this->guzzleClient     = $guzzleClient;
        $this->userRepository   = $userRepository;
        $this->tokenRepository  = $tokenRepository;
        $this->config           = $config;
        $this->cache            = $cache;
        $this->auth             = $auth;
        $this->hasher           = $hasher;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param \Closure $next
     *
     * @return mixed
     * @throws InvalidTokenException
     * @throws Base64DecodeException
     * @throws JWKConverterException
     * @throws GuzzleException
     * @throws InvalidArgumentException
     */
    public function handle($request, Closure $next)
    {
        // Get the current token
        if (($token = $request->bearerToken()) === null) {
            throw new InvalidTokenException('The token is not present.', 401);
        }

        // Try to parse the token
        try {
            $token = $this->parser->parse($token);
        } catch (Exception $exception) {
            throw new InvalidTokenException('The token has invalid format.', 401);
        }

        $signatureKey = null;

        // Check if the token signature is valid
        $signatureKey = $this->cache->get($this->config->get('oauth-token-validator.cache_keys.jwks_signature_public_key'));
        if ($signatureKey === null) {
            // Pull the Auth server public key which can be used for validation
            $response = $this->guzzleClient->get(
                $this->config->get('oauth-token-validator.oauth2_server_url') . '/api/v1/.well-known/jwks.json',
                [
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );

            if ($response->getStatusCode() !== 200) {
                throw new InvalidTokenException(
                    'Access token could not be verified as the JWKS endpoint has returned an error.',
                    401
                );
            }

            $response = json_decode((string)$response->getBody());

            if (!isset($response->keys) || empty($response->keys)) {
                throw new InvalidTokenException(
                    'Access token could not be verified as the signature public key cannot be found in the JWKS set.',
                    401
                );
            }

            // The response might contain multiple keys, find the one used for signing tokens
            foreach ($response->keys as $key) {
                if ($key->use === 'sig') {
                    $signatureKey = $key;
                    break;
                }
            }

            // Store the key in the cache for an hour
            $this->cache->put(
                $this->config->get('oauth-token-validator.cache_keys.jwks_signature_public_key'),
                $signatureKey,
                Carbon::now()->addMinutes(60)
            );
        }

        if ($signatureKey === null) {
            throw new InvalidTokenException(
                'Access token could not be verified as the signature public key is not available.',
                401
            );
        }

        // Validate the signature
        if ($token->verify(new Sha256(), $this->JWKConverter->toPEM((array) $signatureKey)) === false) {
            throw new InvalidTokenException('The token signature is invalid.', 401);
        }

        // Get all claims from the token
        $claims = $token->getClaims();

        // Check if all required claims exist
        foreach ($this->requiredClaims as $claim) {
            if (!array_key_exists($claim, $claims)) {
                throw new InvalidTokenException('The token does not have the required ' . $claim . ' claim.', 401);
            }
        }

        // Check if forbidden claims do not exist
        foreach ($this->forbiddenClaims as $claim) {
            if (array_key_exists($claim, $claims)) {
                throw new InvalidTokenException('The token does contain the forbidden ' . $claim . ' claim.', 401);
            }
        }

        // Get the sub claim which should be a user uuid which should exist in the app database.
        // So the user uuid coming from the IDProvider should be the same user uuid as stored in the app database.
        $user = $this->userRepository->findBy(['where' => [['uuid', '=', $token->getClaim('sub')]]]);

        if ($user === null) {
            throw new InvalidTokenException('The sub claim is invalid.', 401);
        }

        // Check if the token isn't revoked
        $tokenData = $this->tokenRepository->findByTokenId($token->getClaim('jti'));
        if ($tokenData === null
            || $tokenData->revoked === 1
            || !$this->hasher->check($token, $tokenData->accessTokenHash)
        ) {
            throw new InvalidTokenException('The token has been revoked or does not exist anymore.', 401);
        }

        // Check if the token hasn't expired
        if ($token->getClaim('exp') < time()) {
            throw new InvalidTokenException('The token has already expired.', 401);
        }

        // Check if the 'aud' matches the server configured client
        if ($token->getClaim('aud') !== $this->config->get('oauth-token-validator.client_id')) {
            throw new InvalidTokenException('The token aud claim doesnt match the required audience.', 401);
        }

        // Check if the token was issued by the right IDProvider
        if ($token->getClaim('iss') !== $this->config->get('oauth-token-validator.oauth2_server_url')) {
            throw new InvalidTokenException('The token iss claim doesnt match the required issuer.', 401);
        }

        // Log the user to the app as all checks seem to pass.
        // As the API doesn't use sessions this doesn't really login user persistenly.
        // It only store user data for the rest of the code until the entire request is handled.
        $this->auth->login($user);

        return $next($request);
    }
}
