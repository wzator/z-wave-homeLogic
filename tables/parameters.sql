DROP TABLE IF EXISTS `parameters`;
CREATE TABLE IF NOT EXISTS `parameters` (
  `parName` varchar(64) NOT NULL,
  `parValue` int(11) NOT NULL,
  `parTimestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `parName` (`parName`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
