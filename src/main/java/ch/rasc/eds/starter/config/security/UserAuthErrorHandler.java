package ch.rasc.eds.starter.config.security;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

import org.mongodb.morphia.Datastore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.Application;
import ch.rasc.eds.starter.config.AppProperties;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class UserAuthErrorHandler
		implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

	private final Datastore ds;

	private final Integer loginLockAttempts;

	private final Integer loginLockMinutes;

	@Autowired
	public UserAuthErrorHandler(Datastore ds, AppProperties appProperties) {
		this.ds = ds;
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
				user = this.ds.findAndModify(
						this.ds.createQuery(User.class).field(CUser.email)
								.equal(principal).field(CUser.deleted).equal(false),
						this.ds.createUpdateOperations(User.class).inc(CUser.failedLogins,
								1));
			}
			else {
				user = this.ds
						.findAndModify(
								this.ds.createQuery(User.class).field(CUser.id)
										.equal(((MongoUserDetails) principal)
												.getUserDbId()),
						this.ds.createUpdateOperations(User.class).inc(CUser.failedLogins,
								1));
			}

			if (user != null) {
				if (user.getFailedLogins() >= this.loginLockAttempts) {
					if (this.loginLockMinutes != null) {
						this.ds.updateFirst(
								this.ds.createQuery(User.class).field(CUser.id)
										.equal(user.getId()),
								this.ds.createUpdateOperations(User.class).set(
										CUser.lockedOutUntil,
										Date.from(ZonedDateTime.now(ZoneOffset.UTC)
												.plusMinutes(this.loginLockMinutes)
												.toInstant())));
					}
					else {
						this.ds.updateFirst(
								this.ds.createQuery(User.class).field(CUser.id)
										.equal(user.getId()),
								this.ds.createUpdateOperations(User.class)
										.set(CUser.lockedOutUntil,
												Date.from(ZonedDateTime
														.now(ZoneOffset.UTC)
														.plusYears(1000).toInstant())));
					}
				}
			}
			else {
				Application.logger
						.warn("Unknown user login attempt: {}", principal);
			}
		}
		else {
			Application.logger
					.warn("Invalid login attempt: {}", principal);
		}
	}

}
