DROP TABLE IF EXISTS `notifications`;
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `homeid` int(11) NOT NULL,
  `node` int(11) DEFAULT NULL,
  `genre` int(11) DEFAULT NULL,
  `commandclass` int(11) DEFAULT NULL,
  `instance` int(11) DEFAULT NULL,
  `index` int(11) DEFAULT NULL,
  `label` varchar(255) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `type` varchar(32) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `units` varchar(32) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `valueINT` double DEFAULT NULL,
  `valueSTRING` varchar(64) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `timestamp` (`timestamp`),
  KEY `label` (`label`),
  KEY `commandclass` (`commandclass`),
  KEY `node` (`node`),
  KEY `homeid` (`label`,`homeid`,`node`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;

--
-- Wyzwalacze `notifications`
--
DROP TRIGGER IF EXISTS `SWITCHES`;
DELIMITER //
CREATE TRIGGER `SWITCHES` AFTER INSERT ON `notifications`
 FOR EACH ROW BEGIN
IF (NEW.label = 'Switch' AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO switches (node,status,timestamp) VALUES (NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE status = NEW.valueINT, switches.timestamp = NOW();
END IF;

IF (NEW.commandclass = 67 AND NEW.`index` = 1 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO thermostat (node,temp,timestamp) VALUES (NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE thermostat.temp = NEW.valueINT, thermostat.timestamp = NOW();
END IF;

IF (NEW.commandclass = 156 AND NEW.valueINT IS NOT NULL AND NEW.label = 'Flood') THEN
INSERT INTO flood (parentId,homeid,node,instance,valueINT,timestamp) VALUES (NULL,NEW.homeid,NEW.node,NEW.instance,NEW.valueINT,NOW());
END IF;

IF (NEW.commandclass = 49 AND NEW.genre = 1 AND NEW.`index` = 1 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO temperature (node,temp,timestamp) VALUES (NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE temperature.temp = NEW.valueINT, temperature.timestamp = NOW();
END IF;

IF (NEW.commandclass = 50 AND NEW.`index` = 8 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO `power` (`node`,`power`,`timestamp`) VALUES (NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE `power`.`power` = NEW.valueINT, `power`.`timestamp` = NOW();
END IF;


END
//
DELIMITER ;
