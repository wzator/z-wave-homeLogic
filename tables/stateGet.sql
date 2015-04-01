
DROP TABLE IF EXISTS `stateGet`;
CREATE TABLE IF NOT EXISTS `stateGet` (
  `homeid` int(11) DEFAULT NULL,
    `node` int(11) NOT NULL,
    `updateEveryMinutes` int(11) NOT NULL,
    `lastupdate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
PRIMARY KEY (`node`,`homeid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
        