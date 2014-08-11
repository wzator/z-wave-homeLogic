DROP TABLE IF EXISTS `flood`;
CREATE TABLE IF NOT EXISTS `flood` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `parentId` int(11) DEFAULT NULL,
  `homeid` int(11) NOT NULL,
  `node` int(11) NOT NULL,
  `instance` int(11) NOT NULL,
  `valueINT` int(11) NOT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `timestamp` (`timestamp`),
  KEY `valueINT` (`valueINT`),
  KEY `valueINT_2` (`valueINT`,`timestamp`),
  KEY `node` (`node`,`valueINT`),
  KEY `parentId` (`parentId`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
