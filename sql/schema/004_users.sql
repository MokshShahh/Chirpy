-- +goose Up
ALTER TABLE users ALTER COLUMN hashed_password SET DEFAULT 'unset';

-- +goose Down
ALTER TABLE users ALTER COLUMN hashed_password DROP DEFAULT;
