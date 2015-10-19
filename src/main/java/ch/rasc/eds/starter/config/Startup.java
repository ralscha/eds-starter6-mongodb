package ch.rasc.eds.starter.config;

import java.util.Arrays;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import ch.rasc.eds.starter.entity.Authority;
import ch.rasc.eds.starter.entity.User;

@Component
class Startup {

	private final MongoTemplate mongoTemplate;

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public Startup(MongoTemplate mongoTemplate, PasswordEncoder passwordEncoder) {
		this.mongoTemplate = mongoTemplate;
		this.passwordEncoder = passwordEncoder;
		init();
	}

	private void init() {

		if (this.mongoTemplate.count(null, User.class) == 0) {
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
			this.mongoTemplate.save(adminUser);

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
			this.mongoTemplate.save(normalUser);
		}

	}

}
