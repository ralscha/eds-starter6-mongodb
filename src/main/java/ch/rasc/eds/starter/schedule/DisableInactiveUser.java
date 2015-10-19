package ch.rasc.eds.starter.schedule;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

import org.mongodb.morphia.Datastore;
import org.mongodb.morphia.query.Query;
import org.mongodb.morphia.query.UpdateOperations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class DisableInactiveUser {

	private final Datastore ds;

	@Autowired
	public DisableInactiveUser(Datastore ds) {
		this.ds = ds;
	}

	@Scheduled(cron = "0 0 5 * * *")
	public void doCleanup() {
		// Inactivate users that have a lastAccess timestamp that is older than one year
		ZonedDateTime oneYearAgo = ZonedDateTime.now(ZoneOffset.UTC).minusYears(1);

		Query<User> query = this.ds.createQuery(User.class).field(CUser.lastAccess)
				.lessThanOrEq(Date.from(oneYearAgo.toInstant()));

		UpdateOperations<User> update = this.ds.createUpdateOperations(User.class)
				.set(CUser.enabled, false);

		this.ds.update(query, update);
	}

}
