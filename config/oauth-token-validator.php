<?php

return [

    /*
    |--------------------------------------------------------------------------
    | oAuth2
    |--------------------------------------------------------------------------
    |
    | This option controls configuration for the oAuth2 (ID Provider) server
    | so the app can connect to it.
    |
    */
    'oauth2_server_url'     => env('OAUTH2_SERVER_URL'),
    'client_id'             => env('OAUTH2_CLIENT_ID'),
    'client_secret'         => env('OAUTH2_CLIENT_SECRET'),
    'client_redirect_url'   => env('OAUTH2_CLIENT_REDIRECT_URI'),

    'cache_keys' => [
        'jwks_signature_public_key' => env('OAUTH2_JWKS_PUBLIC_KEY_CACHE_NAME', 'oauth.signature_key')
    ]
];
