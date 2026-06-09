-- Initialisation de la base de données pour la cible
CREATE DATABASE IF NOT EXISTS webapp;
USE webapp;

-- Table utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'editor', 'viewer') DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
) ENGINE=InnoDB;

-- Table articles (blog)
CREATE TABLE IF NOT EXISTS articles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    author_id INT,
    status ENUM('draft', 'published', 'archived') DEFAULT 'draft',
    views INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Table commentaires
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    article_id INT NOT NULL,
    author_name VARCHAR(50) DEFAULT 'anonymous',
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Table settings (clé-valeur)
CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(50) PRIMARY KEY,
    setting_value TEXT
) ENGINE=InnoDB;

-- Données de démonstration
INSERT INTO users (username, email, password, role) VALUES
    ('admin', 'admin@target.local', 'admin2025', 'admin'),
    ('editor', 'editor@target.local', 'editor2025', 'editor'),
    ('viewer', 'viewer@target.local', 'viewer2025', 'viewer'),
    ('guest', 'guest@target.local', 'guest123', 'viewer');

INSERT INTO articles (title, content, author_id, status, views) VALUES
    ('Bienvenue sur le serveur', 'Ceci est un article de démonstration.', 1, 'published', 42),
    ('Guide de sécurité', 'Bonnes pratiques pour sécuriser votre serveur.', 2, 'published', 15),
    ('Brouillon confidentiel', 'Notes internes non publiées.', 1, 'draft', 0);

INSERT INTO comments (article_id, author_name, body) VALUES
    (1, 'visitor', 'Très bon article, merci !'),
    (1, 'hacker', 'SELECT * FROM users WHERE 1=1'),
    (2, 'admin', 'N''oubliez pas de changer les mots de passe par défaut.');

INSERT INTO settings (setting_key, setting_value) VALUES
    ('site_name', 'Target Lab'),
    ('debug_mode', 'true'),
    ('db_password', 'mysql_secret_2025'),
    ('api_key', 'sk-target-abc123def456');

-- Permissions
GRANT ALL PRIVILEGES ON webapp.* TO 'webapp_user'@'%' IDENTIFIED BY 'webapp_pass';
FLUSH PRIVILEGES;
