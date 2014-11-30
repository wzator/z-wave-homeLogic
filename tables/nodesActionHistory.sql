
DROP TABLE IF EXISTS `nodesActionHistory`;

CREATE TABLE IF NOT EXISTS `nodesActionHistory` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nodeId` int(11) NOT NULL,
  `timeStart` datetime NOT NULL,
  `timeEnd` datetime NOT NULL,
  `value` double NOT NULL,
  `mtimestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

