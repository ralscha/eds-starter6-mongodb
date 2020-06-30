package ch.rasc.eds.starter.config;

import org.bson.codecs.configuration.CodecRegistries;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;

@Configuration
@EnableConfigurationProperties(MongoProperties.class)
public class MongoConfig {

	@Bean
	public MongoClient mongoClient(MongoProperties properties) {
		return MongoClients.create(properties.getUri());
	}

	@Bean
	public MongoDatabase mongoDatabase(MongoClient mongoClient,
			MongoProperties properties) {
		return mongoClient.getDatabase(properties.getDatabase())
				.withCodecRegistry(CodecRegistries.fromRegistries(
						CodecRegistries.fromProviders(new ListCodec.Provider()),
						CodecRegistries.fromProviders(
								new ch.rasc.eds.starter.config.PojoCodecProvider()),
						MongoClientSettings.getDefaultCodecRegistry()));
	}

}
