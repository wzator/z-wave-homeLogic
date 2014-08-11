DROP TABLE IF EXISTS `zonesFree`;
CREATE TABLE IF NOT EXISTS `zonesFree` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 COMMENT='wolne tak wiec bez alarmu dla tego okresu';
