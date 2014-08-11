DROP TABLE IF EXISTS `wakeup`;
CREATE TABLE IF NOT EXISTS `wakeup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `homeid` int(11) NOT NULL,
  `node` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `homeid` (`homeid`,`node`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
