package ch.rasc.eds.starter.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class UserAuthSuccessfulHandler
		implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

	private final MongoTemplate mongoTemplate;

	@Autowired
	public UserAuthSuccessfulHandler(MongoTemplate mongoTemplate) {
		this.mongoTemplate = mongoTemplate;
	}

	@Override
	public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
		Object principal = event.getAuthentication().getPrincipal();
		if (principal instanceof MongoUserDetails) {
			String userId = ((MongoUserDetails) principal).getUserDbId();

			this.mongoTemplate.updateFirst(
					Query.query(Criteria.where(CUser.id).is(userId)),
					Update.update(CUser.lockedOutUntil, null).set(CUser.failedLogins, 0),
					User.class);

		}
	}
}