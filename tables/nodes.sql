DROP TABLE IF EXISTS `nodes`;
CREATE TABLE IF NOT EXISTS `nodes` (
  `id` int(11) NOT NULL,
  `name` varchar(1024) CHARACTER SET utf8 COLLATE utf8_polish_ci NOT NULL,
  `created` datetime NOT NULL,
  `type` enum('POWER','BATTERY','','') DEFAULT NULL,
  `replaced` date DEFAULT NULL,
  `mtimestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `id` (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

