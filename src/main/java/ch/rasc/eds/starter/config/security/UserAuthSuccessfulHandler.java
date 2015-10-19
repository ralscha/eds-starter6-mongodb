package ch.rasc.eds.starter.config.security;

import org.mongodb.morphia.Datastore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class UserAuthSuccessfulHandler
		implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

	private final Datastore ds;

	@Autowired
	public UserAuthSuccessfulHandler(Datastore ds) {
		this.ds = ds;
	}

	@Override
	public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
		Object principal = event.getAuthentication().getPrincipal();
		if (principal instanceof MongoUserDetails) {
			String userId = ((MongoUserDetails) principal).getUserDbId();

			this.ds.updateFirst(
					this.ds.createQuery(User.class).field(CUser.id).equal(userId),
					this.ds.createUpdateOperations(User.class).unset(CUser.lockedOutUntil)
							.set(CUser.failedLogins, 0));

		}
	}
}