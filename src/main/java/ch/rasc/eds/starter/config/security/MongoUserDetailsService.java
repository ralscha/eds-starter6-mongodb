package ch.rasc.eds.starter.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class MongoUserDetailsService implements UserDetailsService {

	private final MongoTemplate mongoTemplate;

	@Autowired
	public MongoUserDetailsService(MongoTemplate mongoTemplate) {
		this.mongoTemplate = mongoTemplate;
	}

	@Override
	public UserDetails loadUserByUsername(String loginName)
			throws UsernameNotFoundException {
		User user = this.mongoTemplate.findOne(Query.query(
				Criteria.where(CUser.email).is(loginName).and(CUser.deleted).is(false)),
				User.class);
		if (user != null) {
			return new MongoUserDetails(user);
		}

		throw new UsernameNotFoundException(loginName);
	}

}
