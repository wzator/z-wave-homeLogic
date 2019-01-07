DROP TABLE IF EXISTS `nodesZigBee`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `nodesZigBee` (
  `topic` varchar(64) NOT NULL,
  `deviceId` varchar(64) DEFAULT NULL,
  `name` varchar(1024) CHARACTER SET utf8 COLLATE utf8_polish_ci NOT NULL,
  `created` datetime NOT NULL,
  `type` enum('POWER','BATTERY','') DEFAULT NULL,
  `replaced` date DEFAULT NULL,
  `ignoreNode` int(11) DEFAULT '0',
  `alarmNode` int(11) DEFAULT '0',
  `mtimestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `id` (`topic`,`deviceId`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
