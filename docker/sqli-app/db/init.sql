-- Users table with MD5 hashes to crack
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user'
);

-- Products table for search functionality
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL,
    description TEXT,
    secret_flag TEXT
);

INSERT INTO users (username, password, email, role) VALUES
('admin',      '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@shop.local',   'admin'),
('john_doe',   '482c811da5d5b4bc6d497ffa98491e38', 'john@shop.local',    'user'),
('jane_dev',   'e99a18c428cb38d5f260853678922e03', 'jane@shop.local',    'dev'),
('supervisor', '0d107d09f5bbe40cade3de5c71e9e9b7', 'super@shop.local',   'supervisor'),
('guest',      '098f6bcd4621d373cade4e832627b4f6', 'guest@shop.local',   'user'),
('flag_user',  '21232f297a57a5a743894a0e4a801fc3', 'flag@secret.local', 'admin');

INSERT INTO products (name, price, description, secret_flag) VALUES
('Laptop Pro X',     1299.99, 'High performance laptop',  'FLAG{sql_injection_master}'),
('Smart Monitor 27"', 499.00, '4K UHD display',            NULL),
('Wireless Keyboard',  89.99, 'Mechanical switches',       NULL),
('USB-C Hub',          49.99, '7-in-1 multiport adapter', NULL),
('Webcam HD',          79.99, '1080p autofocus webcam',   NULL);
