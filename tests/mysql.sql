DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id`          INT(10) UNSIGNED AUTO_INCREMENT            NOT NULL,
  `email`        VARCHAR(128)                         NOT NULL,
  `password`        VARCHAR(128)                         NOT NULL,
  `status` TINYINT(1) UNSIGNED DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `select` (`email`)
)
  ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

DROP TABLE IF EXISTS `logins`;
CREATE TABLE `logins` (
  `sessions_id`          CHAR(64)            NOT NULL,
  `users_id`          INT(10) UNSIGNED            NOT NULL,
  PRIMARY KEY (`sessions_id`),
  INDEX `login_select` (`users_id`),
  FOREIGN KEY (sessions_id) REFERENCES sessions(id),
  FOREIGN KEY (users_id) REFERENCES users(id)
)
  ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

DROP TABLE IF EXISTS `confirmation`;
CREATE TABLE `confirmation` (
  `users_id`          INT(10) UNSIGNED            NOT NULL,
  `token`          CHAR(48)             NOT NULL,
  `timestamp`   INT(10) UNSIGNED    NOT NULL,
  PRIMARY KEY (`users_id`),
  FOREIGN KEY (users_id) REFERENCES users(id)
)
  ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
