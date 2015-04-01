DROP TABLE IF EXISTS `switches`;
CREATE TABLE IF NOT EXISTS `switches` (
  `homeid` int(11) DEFAULT NULL,
  `node` int(11) NOT NULL,
  `status` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`node`,`homeid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
