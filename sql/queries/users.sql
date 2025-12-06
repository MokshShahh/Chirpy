-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: GetPassword :one
SELECT id,hashed_password,created_at,updated_at from users where email=$1;

-- name: UpdateUser :one
UPDATE users
SET updated_at = NOW(),
    email = $1,
    hashed_password = $2
WHERE id = $3
RETURNING *;

-- name: UpgradeToChirpyRed :one
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1
RETURNING *;