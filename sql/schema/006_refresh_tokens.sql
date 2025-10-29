-- +goose Up
ALTER TABLE refresh_tokens
ADD COLUMN expires_at TIMESTAMP NOT NULL;

-- +goose Down
ALTER TABLE refresh_tokens
DROP COLUMN expires_at;