CREATE DATABASE IF NOT EXISTS auth_service;
USE auth_service;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    otp VARCHAR(10),
    reset_token VARCHAR(255),
    refresh_token VARCHAR(500),
    created_at DATETIME NOT NULL
);