package ch.rasc.eds.starter.config;

import javax.annotation.PostConstruct;

import org.apache.catalina.User;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;

import ch.rasc.eds.starter.entity.CPersistentLogin;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.PersistentLogin;

@Component
public class MongoDb {

	private final MongoDatabase mongoDatabase;

	@Autowired
	public MongoDb(final MongoDatabase mongoDatabase) {
		this.mongoDatabase = mongoDatabase;
	}

	@PostConstruct
	public void createIndexes() {
		this.getCollection(User.class).createIndex(Indexes.ascending(CUser.email),
				new IndexOptions().unique(true));
		this.getCollection(PersistentLogin.class)
				.createIndex(Indexes.ascending(CPersistentLogin.userId));
	}

	public MongoDatabase getMongoDatabase() {
		return this.mongoDatabase;
	}

	public <T> MongoCollection<T> getCollection(Class<T> documentClass) {
		return this.mongoDatabase.getCollection(
				StringUtils.uncapitalize(documentClass.getSimpleName()), documentClass);
	}

	public <T> MongoCollection<T> getCollection(String collectionName,
			Class<T> documentClass) {
		return this.mongoDatabase.getCollection(collectionName, documentClass);
	}

	public MongoCollection<Document> getCollection(String collectionName) {
		return this.mongoDatabase.getCollection(collectionName);
	}

	public long count(Class<?> documentClass) {
		return this.getCollection(documentClass).count();
	}
}
