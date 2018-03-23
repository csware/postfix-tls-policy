CREATE TABLE tls_policy (
    domain varchar(255) NOT NULL,
    policy enum('none', 'may', 'encrypt', 'dane', 'dane-only', 'fingerprint', 'verify', 'secure') NOT NULL,
    params varchar(255),
    PRIMARY KEY (domain)
);
