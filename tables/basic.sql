DROP TABLE IF EXISTS `basic`;
CREATE TABLE IF NOT EXISTS `basic` (
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

--
-- Wyzwalacze `basic`
--
DROP TRIGGER IF EXISTS `basic_update`;

DELIMITER //
CREATE TRIGGER `basic_update` AFTER INSERT ON `basic`
 FOR EACH ROW BEGIN
		IF(NEW.valueINT = '255' AND NEW.node = 5) THEN
			UPDATE security SET event_time_stamp = DATE_FORMAT(NOW(),'%Y%m%d%H%i%S') ORDER BY id DESC LIMIT 1;
		END IF;
	END
//
DELIMITER ;
