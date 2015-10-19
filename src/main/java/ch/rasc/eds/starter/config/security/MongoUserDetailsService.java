package ch.rasc.eds.starter.config.security;

import org.mongodb.morphia.Datastore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

@Component
public class MongoUserDetailsService implements UserDetailsService {

	private final Datastore ds;

	@Autowired
	public MongoUserDetailsService(Datastore ds) {
		this.ds = ds;
	}

	@Override
	public UserDetails loadUserByUsername(String loginName)
			throws UsernameNotFoundException {

		User user = this.ds.createQuery(User.class).field(CUser.email).equal(loginName)
				.field(CUser.deleted).equal(false).get();

		if (user != null) {
			return new MongoUserDetails(user);
		}

		throw new UsernameNotFoundException(loginName);
	}

}
