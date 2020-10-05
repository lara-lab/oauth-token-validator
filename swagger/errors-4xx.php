<?php

/**
 * @OA\Schema(
 *    schema="error4xx",
 *    @OA\Property(
 *      property="code",
 *      type="string",
 *      description="The HTTP error code."
 *    ),
 *    @OA\Property(
 *      property="message",
 *      type="string",
 *      description="The error message."
 *    ),
 *    example={ "message": "The token has been revoked or does not exist anymore.", "code": 401 }
 * )
 */