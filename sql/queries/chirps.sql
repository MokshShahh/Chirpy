-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM CHIRPS ORDER BY created_at;

-- name: GetOneChirp :one
SELECT * FROM CHIRPS where ID = $1;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;

-- name: GetChirpsByAuthor :many
SELECT * FROM CHIRPS WHERE user_id = $1 ORDER BY created_at;