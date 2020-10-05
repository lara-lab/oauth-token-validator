<?php

/**
 * @OA\Schema(
 *    schema="token",
 *    @OA\Property(
 *      property="tokenType",
 *      type="string",
 *      description="The token type (Bearer)."
 *    ),
 *    @OA\Property(
 *      property="accessToken",
 *      type="string",
 *      description="The actual JWT access token content."
 *    ),
 *    @OA\Property(
 *      property="expiresIn",
 *      type="integer",
 *      description="The number of minutes counted from now when the token expires"
 *    ),
 *    example={ "tokenType": "Bearer",
                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjFkODJhYWJiNDYxMzYwOTk0ODZlMWM2NGI5ZjRmYTI3Mjc2NTc2ZjAwMjUzYjk3MmFkMjAzYzlkNGM3NDBjYWZlYmY2MzVkMjNlYjM4ZThjIn0.eyJhdWQiOiJkMzEwOTJhOS1kMzljLTU1YzAtODcxNy1hZmE5NTM1N2Y1MDYiLCJleHAiOjE1NjI2ODExOTUsImp0aSI6IjFkODJhYWJiNDYxMzYwOTk0ODZlMWM2NGI5ZjRmYTI3Mjc2NTc2ZjAwMjUzYjk3MmFkMjAzYzlkNGM3NDBjYWZlYmY2MzVkMjNlYjM4ZThjIiwiaWF0IjoxNTYyNjc1MTk1LCJuYmYiOjE1NjI2NzUxOTUsInN1YiI6IjRmNjNjNTAwLTg0ZjktM2U5Yy1iMmY2LTkwNTQ5ODMwMDY2MSIsInNjb3BlcyI6WyJyZWFkLW5hbWUiLCJyZWFkLWVtYWlsIl0sImlzcyI6Imh0dHA6XC9cL2JiYXV0aC5sb2NhbCIsInNpZCI6Ind2WGltM3hEVHFZVUxSUXgxS2Ewd3licU9KQnVyVmoxeVRUaWtkbDcifQ.YNk2DQZ2eEsgNGF4o8Ehol88qk9ni5VUrIOPHr2-rshzL6DJQLRQ_uQ384hSKg-6NawawQIrR1LwvMrSqi9UrE8fRu9ijdNPT0P_qgkPZ1hU-dfkcRL7HBMvQF8FbTeH-w-zeOGqzaa3U87I2IAkp-BpsLiNXmylTb-v90he8AzYdbfB2BRy6q6XQE9C1b9lqayPtwdDPhIzqlC9AtYKn9n_sAtkiKq2MxB4ilhlJxg1ntLpfQXQNPQLMgL3O4K4xwpSW2WUO6QL_wfek9n7pBDQ0rS8HfxYABCrYNmqanZP4S2yZaEFT4ij_WBzT5xEGd7K3ca1wVV7YPsrnPfa6phIcjPRupxyR3unK-4FwikxGZ0kKZtdtSppSp95DbBN818ZrosQlq17ras_E6CYZEN4XC1VMUmMG-BnH-ixk2T3KkX6u8WdCEVBCL5xqlDrXLgaWQrTWQjrhPQcE0D0Pzf_Jrh-ISzCzDZq7PzJ5UUZu3UnC586rKYssSPre8FmHLO2okYV6-tO7oUDOjY0zfX8UEdjZ6a64YthxRfB45jdjJnUFY9CCUYnXLu9lQvSQEhz1gPkaHBkuQGS9V0ZaCkrmPrO1Lzd0aG-kUsimEVilEj73r0RZnzm5-CKj7A4oVuJCyLvXZInaDdF8jN5e3I69CFARdKbkL-F37Zule8",
                "expiresIn": 6000
              }
 * )
 */
