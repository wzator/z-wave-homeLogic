DROP TABLE IF EXISTS `zonesAlarms`;
CREATE TABLE IF NOT EXISTS `zonesAlarms` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `node` int(11) DEFAULT NULL,
  `dayOfWeek` int(11) NOT NULL,
  `startHour` int(11) NOT NULL,
  `startMinutes` int(11) NOT NULL,
  `endHour` int(11) NOT NULL,
  `endMinutes` int(11) NOT NULL,
  `alarms` int(11) DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 COMMENT='Akcje kiedy alarm ma dzwonic';
