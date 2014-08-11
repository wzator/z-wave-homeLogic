DROP TABLE IF EXISTS `security`;
CREATE TABLE IF NOT EXISTS `security` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `camera` int(11) NOT NULL,
  `filename` varchar(120) NOT NULL,
  `frame` int(11) NOT NULL,
  `file_type` int(11) NOT NULL,
  `time_stamp` datetime NOT NULL,
  `event_time_stamp` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `time_stamp` (`time_stamp`),
  KEY `event_time_stamp` (`event_time_stamp`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
