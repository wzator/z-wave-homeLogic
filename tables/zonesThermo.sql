DROP TABLE IF EXISTS `zonesThermo`;
CREATE TABLE IF NOT EXISTS `zonesThermo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thermonode` int(11) NOT NULL,
  `actiontimestart` time NOT NULL,
  `actiontimeend` time DEFAULT NULL,
  `value` double NOT NULL,
  `active` int(11) DEFAULT NULL,
  `comment` varchar(255) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
