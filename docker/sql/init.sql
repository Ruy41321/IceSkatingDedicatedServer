-- =====================================================
-- Database Schema per Game Database
-- =====================================================

-- Creazione tabella users
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL UNIQUE,
  `psw_md5` varchar(64) NOT NULL,
  `map_completed` int(11) DEFAULT 0,
  `best_score` int(11) DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `idx_username` (`username`),
  INDEX `idx_best_score` (`best_score`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Creazione tabella maps
CREATE TABLE `maps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `map_name` varchar(100) NOT NULL,
  `difficulty` int(1) NOT NULL DEFAULT 1 CHECK (`difficulty` >= 1 AND `difficulty` <= 5),
  `completed_times` int(11) DEFAULT 0,
  `played_times` int(11) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_map_name` (`map_name`),
  INDEX `idx_difficulty` (`difficulty`),
  INDEX `idx_completed_times` (`completed_times`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Creazione tabella user_completed_maps (relazione many-to-many)
CREATE TABLE `user_completed_maps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `map_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_user_map` (`user_id`, `map_id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`map_id`) REFERENCES `maps`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_map_id` (`map_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Creazione vista leaderboard
CREATE VIEW `leaderboard` AS
SELECT 
    RANK() OVER (ORDER BY `best_score` DESC) AS `position`,
    `username`,
    `best_score`
FROM `users`
ORDER BY `best_score` DESC, `username` ASC;

-- =====================================================
-- Query di test per verificare la vista leaderboard
-- =====================================================

-- Uncomment per testare la vista:
-- SELECT * FROM leaderboard LIMIT 10;