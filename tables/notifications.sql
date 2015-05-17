DROP TABLE IF EXISTS `notifications`;
CREATE TABLE IF NOT EXISTS `notifications` (
`id` int(11) NOT NULL,
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
  `year` int(11) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=latin1
/*!50100 PARTITION BY RANGE (`year`)
(PARTITION p0 VALUES LESS THAN (2012) ENGINE = MyISAM,
 PARTITION p1 VALUES LESS THAN (2013) ENGINE = MyISAM,
 PARTITION p2 VALUES LESS THAN (2014) ENGINE = MyISAM,
 PARTITION p3 VALUES LESS THAN (2015) ENGINE = MyISAM,
 PARTITION p4 VALUES LESS THAN (2016) ENGINE = MyISAM,
 PARTITION p5 VALUES LESS THAN (2017) ENGINE = MyISAM,
 PARTITION p6 VALUES LESS THAN (2018) ENGINE = MyISAM,
 PARTITION p7 VALUES LESS THAN (2019) ENGINE = MyISAM,
 PARTITION p8 VALUES LESS THAN (2020) ENGINE = MyISAM,
 PARTITION p9 VALUES LESS THAN (2021) ENGINE = MyISAM,
 PARTITION p10 VALUES LESS THAN (2022) ENGINE = MyISAM,
 PARTITION p11 VALUES LESS THAN (2023) ENGINE = MyISAM,
 PARTITION p12 VALUES LESS THAN (2024) ENGINE = MyISAM,
 PARTITION p13 VALUES LESS THAN (2025) ENGINE = MyISAM,
 PARTITION p14 VALUES LESS THAN (2026) ENGINE = MyISAM,
 PARTITION p15 VALUES LESS THAN (2027) ENGINE = MyISAM,
 PARTITION p16 VALUES LESS THAN MAXVALUE ENGINE = MyISAM) */;

ALTER TABLE `notifications`
 ADD PRIMARY KEY (`id`,`year`), ADD KEY `timestamp` (`timestamp`), ADD KEY `label` (`label`), ADD KEY `commandclass` (`commandclass`), ADD KEY `node` (`node`), ADD KEY `homeid` (`label`,`homeid`,`node`), ADD KEY `year` (`year`);

ALTER TABLE `notifications`
MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Wyzwalacze `notifications`
--
DROP TRIGGER IF EXISTS `SWITCHES`;
DELIMITER //
CREATE TRIGGER `SWITCHES` AFTER INSERT ON `notifications`
 FOR EACH ROW BEGIN
IF (NEW.label = 'Switch' AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO switches (homeid,node,status,timestamp) VALUES (NEW.homeid,NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE status = NEW.valueINT, switches.timestamp = NOW();
END IF;

IF (NEW.commandclass = 67 AND NEW.`index` = 1 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO thermostat (homeid,node,temp,timestamp) VALUES (NEW.homeid,NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE thermostat.temp = NEW.valueINT, thermostat.timestamp = NOW();
END IF;

IF (NEW.commandclass = 156 AND NEW.valueINT IS NOT NULL AND NEW.label = 'Flood') THEN
INSERT INTO flood (parentId,homeid,node,instance,valueINT,timestamp) VALUES (NULL,NEW.homeid,NEW.node,NEW.instance,NEW.valueINT,NOW());
END IF;

IF (NEW.commandclass = 49 AND NEW.genre = 1 AND NEW.`index` = 1 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO temperature (homeid,node,temp,timestamp) VALUES (NEW.homeid,NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE temperature.temp = NEW.valueINT, temperature.timestamp = NOW();
END IF;

IF (NEW.commandclass = 50 AND NEW.`index` = 8 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO `power` (`homeid`,`node`,`power`,`timestamp`) VALUES (NEW.homeid,NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE `power`.`power` = NEW.valueINT, `power`.`timestamp` = NOW();
END IF;

IF (NEW.commandclass = 50 AND NEW.`index` = 0 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO `powerUsage` (`homeid`,`nodeId`,`value`,`mtimestamp`) VALUES (NEW.homeid,NEW.node,NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE `powerUsage`.`value` = NEW.valueINT, `powerUsage`.`mtimestamp` = NOW();
END IF;

IF (NEW.commandclass = 48 AND NEW.`instance` = 1 AND NEW.valueINT IS NOT NULL) THEN
INSERT INTO `sensors` (`homeid`,`node`,`sensor`, `value`,`timestamp`) VALUES (NEW.homeid,NEW.node,NEW.`index`, NEW.valueINT,NOW())
ON DUPLICATE KEY UPDATE `sensors`.`value` = NEW.valueINT, `sensors`.`timestamp` = NOW();
END IF;

END
//
DELIMITER ;
