-- Personal API key used by the `client_credentials` grant (`bw login --apikey`).
-- NULL until the user views/rotates it from Settings > Security > Keys.
ALTER TABLE users ADD COLUMN api_key TEXT;
