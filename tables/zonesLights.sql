DROP TABLE IF EXISTS `zonesLights`;
CREATE TABLE IF NOT EXISTS `zonesLights` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `homeid` int(11) DEFAULT NULL,
  `sensorNode` int(11) NOT NULL,
  `lightNode` int(11) NOT NULL,
  `timeStart` time NOT NULL,
  `timeEnd` time NOT NULL,
  `endNode` int(11) DEFAULT NULL,
  `startedQry` int(11) DEFAULT NULL,
  `dependsOnNode` int(11) DEFAULT NULL,
  `dependsLastAction` int(11) DEFAULT NULL,
  `active` int(11) DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
