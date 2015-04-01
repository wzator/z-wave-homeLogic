DROP TABLE IF EXISTS `thermostat`;
CREATE TABLE IF NOT EXISTS `thermostat` (
  `homeid` int(11) DEFAULT NULL,
  `node` int(11) NOT NULL,
  `temp` double NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`node`,`homeid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
