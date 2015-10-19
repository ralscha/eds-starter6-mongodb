package ch.rasc.eds.starter.config;

import java.util.Arrays;
import java.util.UUID;

import org.mongodb.morphia.Datastore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.Authority;
import ch.rasc.eds.starter.entity.User;

@Component
class Startup {

	private final Datastore ds;

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public Startup(Datastore ds, PasswordEncoder passwordEncoder) {
		this.ds = ds;
		this.passwordEncoder = passwordEncoder;
		init();
	}

	private void init() {

		if (this.ds.getCount(User.class) == 0) {
			// admin user
			User adminUser = new User();
			adminUser.setId(UUID.randomUUID().toString());
			adminUser.setEmail("admin@starter.com");
			adminUser.setFirstName("admin");
			adminUser.setLastName("admin");
			adminUser.setLocale("en");
			adminUser.setPasswordHash(this.passwordEncoder.encode("admin"));
			adminUser.setEnabled(true);
			adminUser.setDeleted(false);
			adminUser.setAuthorities(Arrays.asList(Authority.ADMIN.name()));
			this.ds.save(adminUser);

			// normal user
			User normalUser = new User();
			normalUser.setId(UUID.randomUUID().toString());
			normalUser.setEmail("user@starter.com");
			normalUser.setFirstName("user");
			normalUser.setLastName("user");
			normalUser.setLocale("de");
			normalUser.setPasswordHash(this.passwordEncoder.encode("user"));
			normalUser.setEnabled(true);
			adminUser.setDeleted(false);
			normalUser.setAuthorities(Arrays.asList(Authority.USER.name()));
			this.ds.save(normalUser);
		}

	}

}
