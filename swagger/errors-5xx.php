<?php

/**
 * @OA\Schema(
 *    schema="error5xx",
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
 *    example={ "message": "Internal server error.", "code": 500 }
 * )
 */