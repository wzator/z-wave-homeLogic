

CREATE TABLE IF NOT EXISTS `powerUsage` (
  `homeid` int(11) DEFAULT NULL,
  `nodeId` int(11) NOT NULL,
  `value` double NOT NULL,
  `mtimestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`nodeId`,`homeid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

