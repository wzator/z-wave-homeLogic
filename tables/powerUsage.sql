

CREATE TABLE IF NOT EXISTS `powerUsage` (
  `nodeId` int(11) NOT NULL,
  `value` double NOT NULL,
  `mtimestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`nodeId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

