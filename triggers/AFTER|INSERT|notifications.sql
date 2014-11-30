BEGIN
		IF(NEW.valueINT = '255' AND NEW.node = 5) THEN
			UPDATE security SET event_time_stamp = DATE_FORMAT(NOW(),'%Y%m%d%H%i%S') ORDER BY id DESC LIMIT 1;
		END IF;
	END
