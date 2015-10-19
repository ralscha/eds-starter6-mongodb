package ch.rasc.eds.starter.config.security;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.Application;
import ch.rasc.eds.starter.config.AppProperties;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class UserAuthErrorHandler
		implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

	private final MongoTemplate mongoTemplate;

	private final Integer loginLockAttempts;

	private final Integer loginLockMinutes;

	@Autowired
	public UserAuthErrorHandler(MongoTemplate mongoTemplate,
			AppProperties appProperties) {
		this.mongoTemplate = mongoTemplate;
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
				user = this.mongoTemplate.findAndModify(
						Query.query(Criteria.where(CUser.email).is(principal)
								.and(CUser.deleted).is(false)),
						new Update().inc(CUser.failedLogins, 1),
						FindAndModifyOptions.options().returnNew(true).upsert(false),
						User.class);
			}
			else {
				user = this.mongoTemplate
						.findAndModify(
								Query.query(Criteria.where(CUser.id)
										.is(((MongoUserDetails) principal)
												.getUserDbId())),
						new Update().inc(CUser.failedLogins, 1),
						FindAndModifyOptions.options().returnNew(true).upsert(false),
						User.class);
			}

			if (user != null) {
				if (user.getFailedLogins() >= this.loginLockAttempts) {
					if (this.loginLockMinutes != null) {
						this.mongoTemplate.updateFirst(
								Query.query(Criteria.where(CUser.id).is(user.getId())),
								Update.update(CUser.lockedOutUntil,
										Date.from(ZonedDateTime.now(ZoneOffset.UTC)
												.plusMinutes(this.loginLockMinutes)
												.toInstant())),
								User.class);
					}
					else {
						this.mongoTemplate.updateFirst(
								Query.query(Criteria.where(CUser.id).is(user.getId())),
								Update.update(CUser.lockedOutUntil,
										Date.from(ZonedDateTime.now(ZoneOffset.UTC)
												.plusYears(1000).toInstant())),
								User.class);
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
