<?php

namespace AB\OAuthTokenValidator\Models;

use Illuminate\Database\Eloquent\Model;

class OAuthTokenModel extends Model
{
    /**
     * Defines the column name for createdAt.
     */
    const CREATED_AT = 'createdAt';

    /**
     * Defines the column name for updatedAt.
     */
    const UPDATED_AT = 'updatedAt';

    /**
     * Indicates whether attributes are snake cased on arrays.
     *
     * @var bool
     */
    public static $snakeAttributes = false;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'oauth_user_tokens';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'userId', 'accessTokenHash', 'refreshToken'
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'userId'                => 'integer',
        'accessTokenHash'       => 'string',
        'refreshToken'          => 'string',
        'accessTokenExpiresAt'  => 'timestamp',
        'createdAt'             => 'timestamp',
        'updatedAt'             => 'timestamp',
    ];
}
