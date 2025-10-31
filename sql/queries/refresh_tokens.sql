-- name: CreateToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at,revoked_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW()+ INTERVAL '60 days',
    NULL
)
RETURNING *;

-- name: FindToken :one
SELECT * from refresh_tokens WHERE token=$1; 

-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
    updated_at = NOW()
WHERE token = $1;