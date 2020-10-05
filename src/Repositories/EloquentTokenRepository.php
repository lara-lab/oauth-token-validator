<?php

namespace AB\OAuthTokenValidator\Repositories;

use AB\OAuthTokenValidator\Contracts\TokenRepositoryContract;
use AB\OAuthTokenValidator\Exceptions\ModelNotCreatedException;
use AB\OAuthTokenValidator\Models\OAuthTokenModel;

class EloquentTokenRepository implements TokenRepositoryContract
{
    /**
     * @var OAuthTokenModel
     */
    private $oAuthTokenModel;

    /**
     * EloquentTokenRepository constructor.
     *
     * @param OAuthTokenModel $oAuthTokenModel
     */
    public function __construct(OAuthTokenModel $oAuthTokenModel)
    {
        $this->oAuthTokenModel = $oAuthTokenModel;
    }

    /**
     * Find a record by $tokenId.
     *
     * @param string $tokenId
     *
     * @return OAuthTokenModel|null
     */
    public function findByTokenId(string $tokenId): ?OAuthTokenModel
    {
        return $this->oAuthTokenModel->newQuery()->where('id', $tokenId)->first();
    }

    /**
     * Find a record by $userId.
     *
     * @param int $userId
     *
     * @return OAuthTokenModel|null
     */
    public function findByUserId(int $userId): ?OAuthTokenModel
    {
        return $this->oAuthTokenModel->newQuery()->where('userId', $userId)->first();
    }

    /**
     * Find a record by $refreshToken.
     *
     * @param string $refreshToken
     *
     * @return OAuthTokenModel|null
     */
    public function findByRefreshToken(string $refreshToken): ?OAuthTokenModel
    {
        return $this->oAuthTokenModel->newQuery()->where('refreshToken', $refreshToken)->first();
    }

    /**
     * Deletes all resources which match the given $userId.
     *
     * @param int $userId
     *
     * @return bool
     */
    public function deleteByUserId(int $userId): bool
    {
        return $this->oAuthTokenModel->newQuery()->where('userId', $userId)->delete();
    }

    /**
     * Create a new record.
     *
     * @param array $data
     *
     * @return OAuthTokenModel
     *
     * @throws ModelNotCreatedException
     */
    public function create(array $data): OAuthTokenModel
    {
        $oAuthTokenModel                        = $this->oAuthTokenModel->newInstance();
        $oAuthTokenModel->id                    = $data['id'];
        $oAuthTokenModel->userId                = $data['userId'];
        $oAuthTokenModel->accessTokenHash       = $data['accessTokenHash'];
        $oAuthTokenModel->refreshToken          = $data['refreshToken'];
        $oAuthTokenModel->accessTokenExpiresAt  = $data['accessTokenExpiresAt'];
        $success                                = $oAuthTokenModel->save();

        if (!$success) {
            throw new ModelNotCreatedException('ModelNotCreatedException', 500);
        }

        return $oAuthTokenModel;
    }
}
