CREATE TABLE `users` (
  `id`          INT(10) UNSIGNED AUTO_INCREMENT            NOT NULL,
  `email`        VARCHAR(128)                         NOT NULL,
  `password`        VARBINARY(128)                         NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `select` (`email`)
)
  ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
