package ch.rasc.eds.starter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "mongodb")
@Component
public class MongoProperties {

	private String uri = "mongodb://localhost";

	private String database;

	public String getUri() {
		return this.uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public String getDatabase() {
		return this.database;
	}

	public void setDatabase(String database) {
		this.database = database;
	}

}
