DROP TABLE IF EXISTS `tv`;
CREATE TABLE IF NOT EXISTS `tv` (
  `tv_id` int(11) NOT NULL AUTO_INCREMENT,
  `tv_weekday` int(11) NOT NULL,
  `tv_hour` int(11) NOT NULL,
  `tv_minutes` int(11) NOT NULL,
  `tv_no` int(11) DEFAULT NULL,
  `tv_action` enum('POWERON','POWEROFF','','') NOT NULL,
  `tv_keys` varchar(1024) DEFAULT NULL,
  `tv_lastaction` date DEFAULT NULL,
  `tv_active` int(11) DEFAULT '0',
  `tv_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`tv_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;
