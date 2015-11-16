package ch.rasc.eds.starter.config.security;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Updates;

import ch.rasc.eds.starter.Application;
import ch.rasc.eds.starter.config.AppProperties;
import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class UserAuthErrorHandler
		implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

	private final MongoDb mongoDb;

	private final Integer loginLockAttempts;

	private final Integer loginLockMinutes;

	@Autowired
	public UserAuthErrorHandler(MongoDb mongoDb,
			AppProperties appProperties) {
		this.mongoDb = mongoDb;
		this.loginLockAttempts = appProperties.getLoginLockAttempts();
		this.loginLockMinutes = appProperties.getLoginLockMinutes();
	}

	@Override
	public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
		updateLockedProperties(event);
	}

	private void updateLockedProperties(AuthenticationFailureBadCredentialsEvent event) {
		Object principal = event.getAuthentication().getPrincipal();

		if (this.loginLockAttempts != null && (principal instanceof String
				|| principal instanceof MongoUserDetails)) {

			User user = null;
			if (principal instanceof String) {
				
				user = mongoDb.getCollection(User.class).findOneAndUpdate(
						Filters.and(Filters.eq(CUser.email, principal), Filters.eq(CUser.deleted, false)),
						Updates.inc(CUser.failedLogins, 1),
						new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER).upsert(false));
				
//				user = this.mongoDb.findAndModify(
//						Query.query(Criteria.where(CUser.email).is(principal)
//								.and(CUser.deleted).is(false)),
//						new Update().inc(CUser.failedLogins, 1),
//						FindAndModifyOptions.options().returnNew(true).upsert(false),
//						User.class);
			}
			else {
				
				user = mongoDb.getCollection(User.class).findOneAndUpdate(
						Filters.eq(CUser.id, ((MongoUserDetails) principal).getUserDbId()),
						Updates.inc(CUser.failedLogins, 1),
						new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER).upsert(false));				
				
//				user = this.mongoDb
//						.findAndModify(
//								Query.query(Criteria.where(CUser.id)
//										.is(((MongoUserDetails) principal)
//												.getUserDbId())),
//						new Update().inc(CUser.failedLogins, 1),
//						FindAndModifyOptions.options().returnNew(true).upsert(false),
//						User.class);
			}

			if (user != null) {
				if (user.getFailedLogins() >= this.loginLockAttempts) {
					if (this.loginLockMinutes != null) {
						mongoDb.getCollection(User.class).updateOne(Filters.eq(CUser.id, user.getId()),
								Updates.set(CUser.lockedOutUntil, Date.from(ZonedDateTime.now(ZoneOffset.UTC)
										.plusMinutes(this.loginLockMinutes)
										.toInstant())));
								
//						this.mongoDb.updateFirst(
//								Query.query(Criteria.where(CUser.id).is(user.getId())),
//								Update.update(CUser.lockedOutUntil,
//										Date.from(ZonedDateTime.now(ZoneOffset.UTC)
//												.plusMinutes(this.loginLockMinutes)
//												.toInstant())),
//								User.class);
					}
					else {
						mongoDb.getCollection(User.class).updateOne(Filters.eq(CUser.id, user.getId()),
								Updates.set(CUser.lockedOutUntil, Date.from(ZonedDateTime.now(ZoneOffset.UTC)
										.plusYears(1000).toInstant())));
						
//						this.mongoDb.updateFirst(
//								Query.query(Criteria.where(CUser.id).is(user.getId())),
//								Update.update(CUser.lockedOutUntil,
//										Date.from(ZonedDateTime.now(ZoneOffset.UTC)
//												.plusYears(1000).toInstant())),
//								User.class);
					}
				}
			}
			else {
				Application.logger.warn("Unknown user login attempt: {}", principal);
			}
		}
		else {
			Application.logger.warn("Invalid login attempt: {}", principal);
		}
	}

}
