-- IronShield FIM - Schéma MySQL
-- Charset utf8mb4 recommandé (alwaysdata / MySQL 8)

CREATE TABLE IF NOT EXISTS clients (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    telephone VARCHAR(30) DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS licenses (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id INT UNSIGNED NOT NULL,
    license_key CHAR(29) NOT NULL UNIQUE,           -- format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    max_machines INT UNSIGNED NOT NULL DEFAULT 1,
    tier ENUM('trial','standard','pro','enterprise') NOT NULL DEFAULT 'trial',
    status ENUM('active','suspended','revoked','expired') NOT NULL DEFAULT 'active',
    starts_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    INDEX idx_license_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS machines (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    license_id INT UNSIGNED NOT NULL,
    hardware_id CHAR(64) NOT NULL,                  -- SHA-256 hex du fingerprint machine
    hostname VARCHAR(150) DEFAULT NULL,
    os_version VARCHAR(100) DEFAULT NULL,
    agent_version VARCHAR(30) DEFAULT NULL,
    activation_token CHAR(64) NOT NULL,              -- token opaque, renvoyé à l'agent
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active','revoked') NOT NULL DEFAULT 'active',
    UNIQUE KEY uniq_license_hw (license_id, hardware_id),
    FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE,
    INDEX idx_machine_token (activation_token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS file_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    machine_id INT UNSIGNED NOT NULL,
    path VARCHAR(1024) NOT NULL,
    event_type ENUM('created','modified','deleted','renamed') NOT NULL,
    sha256 CHAR(64) DEFAULT NULL,
    severity ENUM('info','warning','critical') NOT NULL DEFAULT 'info',
    occurred_at DATETIME NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_event_machine_date (machine_id, occurred_at),
    INDEX idx_event_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS alerts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    machine_id INT UNSIGNED NOT NULL,
    file_event_id BIGINT UNSIGNED DEFAULT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    acknowledged TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL,
    INDEX idx_alert_ack (acknowledged)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS api_rate_buckets (
    ip_address VARCHAR(45) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    bucket BIGINT NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (ip_address, endpoint, bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Purge recommandée en tâche planifiée (les buckets de plus de 24h ne
-- servent plus à rien) :
-- DELETE FROM api_rate_buckets WHERE bucket < UNIX_TIMESTAMP(NOW() - INTERVAL 1 DAY);

-- Liste blanche gérée côté serveur : permet au support de neutraliser un
-- faux positif signalé par un client SANS avoir à toucher chaque poste.
-- L'agent ne consulte pas cette table directement (il reste offline-first) ;
-- elle sert de source de vérité pour générer la config poussée aux agents
-- lors de leur prochaine synchronisation, et pour l'audit du support.
CREATE TABLE IF NOT EXISTS whitelist_entries (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    license_id INT UNSIGNED NOT NULL,
    entry_type ENUM('path','process_name','hash') NOT NULL,
    value VARCHAR(1024) NOT NULL,
    reason VARCHAR(255) DEFAULT NULL,
    created_by VARCHAR(150) DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE,
    INDEX idx_whitelist_license (license_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
