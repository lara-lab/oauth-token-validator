<?php

namespace AB\OAuthTokenValidator\Contracts;

interface TokenRepositoryContract
{
    /**
     * Finds a resource which matches the given $userId.
     *
     * @param int $userId
     *
     * @return mixed
     */
    public function findByUserId(int $userId);

    /**
     * Finds a resource which matches the given $refreshToken.
     *
     * @param string $refreshToken
     *
     * @return mixed
     */
    public function findByRefreshToken(string $refreshToken);

    /**
     * Delete all resources which match the given $userId.
     *
     * @param int $userId
     *
     * @return mixed
     */
    public function deleteByUserId(int $userId);

    /**
     * Creates a new resource model.
     *
     * @param array $data
     *
     * @return mixed
     */
    public function create(array $data);
}
