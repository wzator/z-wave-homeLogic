DROP TABLE IF EXISTS `sensors`;
CREATE TABLE IF NOT EXISTS `sensors` (
  `node` int(11) NOT NULL,
  `homeid` int(11) NOT NULL,
  `sensor` int(11) NOT NULL,
  `value` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

ALTER TABLE `sensors`
 ADD PRIMARY KEY (`node`,`homeid`,`sensor`);
