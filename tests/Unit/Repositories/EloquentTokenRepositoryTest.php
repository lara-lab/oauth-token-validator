<?php

namespace Franklin\OAuth2Client\Tests\Unit\Repositories;

use Carbon\Carbon;
use Franklin\OAuth2Client\Exceptions\ModelNotCreatedException;
use Franklin\OAuth2Client\Models\OAuthTokenModel;
use Franklin\OAuth2Client\Repositories\EloquentTokenRepository;
use Franklin\OAuth2Client\Tests\AbstractTestCase;
use Illuminate\Database\Eloquent\Builder;
use Mockery;

class EloquentTokenRepositoryTest extends AbstractTestCase
{
    /**
     * @var \Mockery\Mock|OAuthTokenModel
     */
    private $mockTokenModel;

    /**
     * @var \Mockery\Mock|Builder;
     */
    private $mockBuilder;

    /**
     * Test initialisation.
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->mockTokenModel = Mockery::mock(OAuthTokenModel::class);
        $this->mockBuilder    = Mockery::mock(Builder::class);
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
     * Test finding a single resource based on provided conditions.
     *
     * @return void
     */
    public function testFindByTokenId(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('id', 1)->once()->andReturnSelf()
            ->shouldReceive('first')->once()->andReturn(new OAuthTokenModel());

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $result = $refreshTokenRepository->findByTokenId(1);

        $this->assertEquals(OAuthTokenModel::class, get_class($result));
    }

    /**
     * Test finding a single, non-existing resource based on provided conditions.
     *
     * @return void
     */
    public function testFindByTokenNotFound(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('id', 1)->once()->andReturnSelf()
            ->shouldReceive('first')->once()->andReturn(null);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $this->assertNull($refreshTokenRepository->findByTokenId(1));
    }

    /**
     * Test finding a single resource based on provided conditions.
     *
     * @return void
     */
    public function testFindByUserId(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('userId', 1)->once()->andReturnSelf()
            ->shouldReceive('first')->once()->andReturn(new OAuthTokenModel());

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $result = $refreshTokenRepository->findByUserId(1);

        $this->assertEquals(OAuthTokenModel::class, get_class($result));
    }

    /**
     * Test finding a single, non-existing resource based on provided conditions.
     *
     * @return void
     */
    public function testFindByNotFound(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('userId', 1)->once()->andReturnSelf()
            ->shouldReceive('first')->once()->andReturn(null);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $this->assertNull($refreshTokenRepository->findByUserId(1));
    }

    /**
     * Test finding a single resource based on provided conditions.
     *
     * @return void
     */
    public function testFindByRefreshToken(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('refreshToken', 'token')->once()->andReturnSelf()
            ->shouldReceive('first')->once()->andReturn(new OAuthTokenModel());

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $result = $refreshTokenRepository->findByRefreshToken('token');

        $this->assertEquals(OAuthTokenModel::class, get_class($result));
    }

    /**
     * Test finding a single, non-existing resource based on provided conditions.
     *
     * @return void
     */
    public function testFindByRefreshTokenNotFound(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('refreshToken', 'token')->once()->andReturnSelf()
            ->shouldReceive('first')->once()->andReturn(null);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $this->assertNull($refreshTokenRepository->findByRefreshToken('token'));
    }

    /**
     * Test deleting a single resource based on provided conditions.
     *
     * @return void
     */
    public function testDeleteByUserId(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('userId', 1)->once()->andReturnSelf()
            ->shouldReceive('delete')->once()->andReturn(true);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $this->assertTrue($refreshTokenRepository->deleteByUserId(1));
    }

    /**
     * Test deleting a single, non-existing resource based on provided conditions.
     *
     * @return void
     */
    public function testDeleteByUserIdNotFound(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newQuery')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('where')->with('userId', 1)->once()->andReturnSelf()
            ->shouldReceive('delete')->once()->andReturn(false);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $this->assertFalse($refreshTokenRepository->deleteByUserId(1));
    }

    /**
     * Test creating a single resource.
     *
     * @return void
     */
    public function testCreate(): void
    {
        $this->mockTokenModel
            ->shouldReceive('newInstance')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('id', 'token-jti')->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('userId', 1)->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('accessTokenHash', 'hash-string')->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('refreshToken', 'token')->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('accessTokenExpiresAt', Carbon::now()->toDateTimeString())->once()->andReturnSelf()
            ->shouldReceive('save')->once()->andReturn(true);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $result = $refreshTokenRepository->create(['id' => 'token-jti', 'userId' => 1, 'accessTokenHash' => 'hash-string', 'refreshToken' => 'token', 'accessTokenExpiresAt' =>  Carbon::now()->toDateTimeString()]);

        $this->assertEquals(get_class($this->mockTokenModel), get_class($result));
    }

    /**
     * Test creating a single, an exception is throws.
     *
     * @return void
     */
    public function testCreateException(): void
    {
        $this->expectException(ModelNotCreatedException::class);
        $this->expectExceptionCode(500);
        $this->expectExceptionMessage('ModelNotCreatedException');

        $this->mockTokenModel
            ->shouldReceive('newInstance')->withNoArgs()->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('id', 'token-jti')->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('userId', 1)->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('accessTokenHash', 'hash-string')->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('refreshToken', 'token')->once()->andReturnSelf()
            ->shouldReceive('setAttribute')->with('accessTokenExpiresAt', Carbon::now()->toDateTimeString())->once()->andReturnSelf()
            ->shouldReceive('save')->once()->andReturn(false);

        $refreshTokenRepository = new EloquentTokenRepository($this->mockTokenModel);

        $this->assertFalse($refreshTokenRepository->create(['id' => 'token-jti', 'userId' => 1, 'accessTokenHash' => 'hash-string', 'refreshToken' => 'token', 'accessTokenExpiresAt' =>  Carbon::now()->toDateTimeString()]));
    }
}
