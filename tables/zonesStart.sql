DROP TABLE IF EXISTS `zonesStart`;
CREATE TABLE IF NOT EXISTS `zonesStart` (
`id` int(11) NOT NULL,
  `homeid` int(11) DEFAULT NULL,
  `startNode` int(11) NOT NULL,
  `endNode` int(11) NOT NULL,
  `startValue` double NOT NULL,
  `endValue` int(11) NOT NULL,
  `actiontimestart` datetime NOT NULL,
  `actiontimeend` datetime DEFAULT NULL,
  `commandclassStart` int(11) DEFAULT NULL,
  `commandclassEnd` int(11) DEFAULT NULL,
  `instanceStart` int(11) DEFAULT NULL,
  `instanceEnd` int(11) DEFAULT NULL,
  `indexStart` int(11) DEFAULT NULL,
  `indexEnd` int(11) DEFAULT NULL,
  `delayTimeMin` int(11) DEFAULT NULL,
  `lastAction` datetime DEFAULT NULL,
  `stampOnly` int(11) DEFAULT '0',
  `active` int(11) DEFAULT NULL,
  `parentRule` int(11) DEFAULT NULL,
  `ruleId` int(11) DEFAULT NULL,
  `comment` varchar(255) CHARACTER SET utf8 COLLATE utf8_polish_ci DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

ALTER TABLE `zonesStart`
 ADD PRIMARY KEY (`id`), ADD KEY `ruleId` (`ruleId`);

ALTER TABLE `zonesStart`
MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
