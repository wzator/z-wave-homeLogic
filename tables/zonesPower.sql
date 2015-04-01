DROP TABLE IF EXISTS `zonesPower`;
CREATE TABLE IF NOT EXISTS `zonesPower` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `homeid` int(11) DEFAULT NULL,
  `powernode` int(11) NOT NULL,
  `actiontimestart` time NOT NULL,
  `actiontimeend` time DEFAULT NULL,
  `value` int(11) NOT NULL,
  `nomove` int(11) DEFAULT NULL,
  `status` int(11) DEFAULT NULL,
  `active` int(11) DEFAULT NULL,
  `comment` varchar(255) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `commandclass` int(11) NOT NULL,
  `result` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
