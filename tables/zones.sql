DROP TABLE IF EXISTS `zones`;
CREATE TABLE IF NOT EXISTS `zones` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dayOfWeek` int(11) NOT NULL,
  `startHour` int(11) NOT NULL,
  `startMinutes` int(11) NOT NULL,
  `endHour` int(11) NOT NULL,
  `endMinutes` int(11) NOT NULL,
  `active` int(11) NOT NULL,
  `node` int(11) DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 COMMENT='Powiadomienia czujki na smsa';
