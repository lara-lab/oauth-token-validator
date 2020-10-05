<?php

namespace AB\OAuthTokenValidator\Providers;

use AB\OAuthTokenValidator\Contracts\TokenRepositoryContract;
use AB\OAuthTokenValidator\Repositories\EloquentTokenRepository;
use Illuminate\Cache\CacheServiceProvider;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Hashing\HashServiceProvider;
use Illuminate\Support\ServiceProvider;

class OAuth2ClientServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     * @throws BindingResolutionException
     */
    public function register(): void
    {
        // Define which TokenRepository implementation should be used
        $this->app->bind(
            TokenRepositoryContract::class,
            EloquentTokenRepository::class
        );

        // Normally, the CacheServiceProvider is marked as 'deferred' which means it's not loaded before
        // the OAuth2ClientServiceProvider service provider needs it. To fix it, we need to register it manually.
        // This package relies on cache, which relies on the Cache Store that's how the Store becomes available.
//        $this->app->register(CacheServiceProvider::class);

        // The same is required for hashing.
        $this->app->register(HashServiceProvider::class);

        // Register our controller
        $this->app->make('AB\OAuthTokenValidator\Http\Controllers\OAuth2Controller');

        // Define what can be published
        $this->offerPublishing();
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot(): void
    {
        // Include the package routes
        $this->loadRoutesFrom(__DIR__.'/../Routes/routes.php');

        // Load migrations
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
    }

    /**
     * Setup the resource publishing groups for Passport.
     *
     * @return void
     * @throws BindingResolutionException
     */
    protected function offerPublishing(): void
    {
        // work out the config path to publish (can't just use the config_path helper here; we're not using framework)
        $path       = $this->app->make('path.config') . DIRECTORY_SEPARATOR . 'oauth-token-validator.php';
//        $token      = $this->app->make('path.config') . DIRECTORY_SEPARATOR . '../swagger/schemas/token.php';
//        $errors4xx  = $this->app->make('path.config') . DIRECTORY_SEPARATOR . '../swagger/errors/errors-4xx.php';
//        $errors5xx  = $this->app->make('path.config') . DIRECTORY_SEPARATOR . '../swagger/errors/errors-5xx.php';

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/oauth-token-validator.php' => $path,
            ], 'oauth-token-validator-config');

            // To generate a full swagger documentation we have to copy the new file into the swagger folder
            // In the main project
//            $this->publishes([
//                __DIR__.'/../../swagger/errors-4xx.php' => $errors4xx,
//            ], 'oauth2client-errors4xx');
//
//            $this->publishes([
//                __DIR__.'/../../swagger/errors-4xx.php' => $errors5xx,
//            ], 'oauth2client-errors5xx');
//
//            $this->publishes([
//                __DIR__.'/../../swagger/token.php' => $token,
//            ], 'oauth2client-token');
        }
    }
}
