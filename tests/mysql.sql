CREATE TABLE `users` (
  `id`          INT(10) UNSIGNED AUTO_INCREMENT            NOT NULL,
  `email`        VARCHAR(128)                         NOT NULL,
  `password`        VARCHAR(128)                         NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `select` (`email`)
)
  ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

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
