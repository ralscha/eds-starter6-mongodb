package ch.rasc.eds.starter.config;

import java.net.UnknownHostException;

import org.mongodb.morphia.Datastore;
import org.mongodb.morphia.Morphia;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.WriteConcern;

import ch.rasc.eds.starter.entity.User;

@Configuration
@EnableConfigurationProperties(MongoProperties.class)
public class MongoConfig {

	@Bean
	public MongoClient mongoClient(MongoProperties properties, Environment environment)
			throws UnknownHostException {
		MongoClientOptions options = MongoClientOptions.builder()
				.writeConcern(WriteConcern.JOURNALED).build();

		return properties.createMongoClient(options, environment);
	}

	@Bean
	public Morphia morphia() {
		Morphia morphia = new Morphia();
		morphia.mapPackageFromClass(User.class);
		return morphia;
	}

	@Bean
	public Datastore datastore(Morphia morphia, MongoClient mongoClient,
			MongoProperties properties) {
		Datastore datastore = morphia.createDatastore(mongoClient,
				properties.getDatabase());
		datastore.ensureIndexes();
		return datastore;
	}
}
