-- =====================================================================
-- init.sql — Script d'initialisation de la base SQLite du SQLi Shop
-- =====================================================================
-- Crée les tables users et products avec des données de test.
-- Les mots de passe sont hashés en MD5 (algorithme FAIBLE, non salé)
-- pour permettre le cracking de hash dans le cadre du lab.
-- Un flag caché est présent dans les produits (secret_flag).
-- =====================================================================

-- Users table — Stocke les utilisateurs avec mots de passe hashés MD5
-- Colonnes :
--   id       → identifiant unique (clé primaire, auto-incrément)
--   username → nom d'utilisateur (texte, obligatoire)
--   password → hash MD5 du mot de passe (texte, obligatoire) — NON SALÉ
--   email    → adresse email (optionnelle)
--   role     → rôle de l'utilisateur (par défaut 'user')
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user'
);

-- Products table — Produits du shop avec flag caché
-- Colonnes :
--   id          → identifiant unique (clé primaire, auto-incrément)
--   name        → nom du produit (obligatoire)
--   price       → prix (nombre réel/décimal)
--   description → description textuelle
--   secret_flag → colonne cachée contenant le FLAG — non affichée dans
--                 l'interface normale, à extraire via injection SQL
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL,
    description TEXT,
    secret_flag TEXT
);

-- Insertion des utilisateurs avec leurs hashs MD5 (volontairement faibles) :
-- admin      : password  (hash: 5f4dcc3b...) — classique, crackable
-- john_doe   : password123
-- jane_dev   : abc123
-- supervisor : letmein
-- guest      : test
-- flag_user  : admin       (hash: 21232f29...) — même mot de passe que admin = admin
INSERT INTO users (username, password, email, role) VALUES
('admin',      '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@shop.local',   'admin'),
('john_doe',   '482c811da5d5b4bc6d497ffa98491e38', 'john@shop.local',    'user'),
('jane_dev',   'e99a18c428cb38d5f260853678922e03', 'jane@shop.local',    'dev'),
('supervisor', '0d107d09f5bbe40cade3de5c71e9e9b7', 'super@shop.local',   'supervisor'),
('guest',      '098f6bcd4621d373cade4e832627b4f6', 'guest@shop.local',   'user'),
('flag_user',  '21232f297a57a5a743894a0e4a801fc3', 'flag@secret.local', 'admin');

-- Insertion des produits — le FLAG est dans secret_flag du premier produit
-- Pour extraire le flag : injection UNION sur la colonne secret_flag
INSERT INTO products (name, price, description, secret_flag) VALUES
('Laptop Pro X',     1299.99, 'High performance laptop',  'FLAG{sql_injection_master}'),
('Smart Monitor 27"', 499.00, '4K UHD display',            NULL),
('Wireless Keyboard',  89.99, 'Mechanical switches',       NULL),
('USB-C Hub',          49.99, '7-in-1 multiport adapter', NULL),
('Webcam HD',          79.99, '1080p autofocus webcam',   NULL);
