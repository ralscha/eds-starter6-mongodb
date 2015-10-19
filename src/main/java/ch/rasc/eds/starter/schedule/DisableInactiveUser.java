package ch.rasc.eds.starter.schedule;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class DisableInactiveUser {

	private final MongoTemplate mongoTemplate;

	@Autowired
	public DisableInactiveUser(MongoTemplate mongoTemplate) {
		this.mongoTemplate = mongoTemplate;
	}

	@Scheduled(cron = "0 0 5 * * *")
	public void doCleanup() {
		// Inactivate users that have a lastAccess timestamp that is older than one year
		ZonedDateTime oneYearAgo = ZonedDateTime.now(ZoneOffset.UTC).minusYears(1);
		this.mongoTemplate.updateMulti(
				Query.query(Criteria.where(CUser.lastAccess).lte(oneYearAgo)),
				Update.update(CUser.enabled, false), User.class);

	}

}
