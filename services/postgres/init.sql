CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    public_key VARCHAR(450) NOT NULL -- Considering default 2048 RSA key (from PyCryptoDome).
);
