CREATE TABLE `sessions` (
  `id`          CHAR(64)            NOT NULL,
  `data`        TEXT                         DEFAULT NULL,
  `timestamp`   INT(10) UNSIGNED    NOT NULL,
  `remember_me` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `garbage_collection_index` (`remember_me`, `timestamp`)
)
  ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
