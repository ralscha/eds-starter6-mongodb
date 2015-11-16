package ch.rasc.eds.starter.config;

import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

@Component
public class MongoDb {

	private final MongoDatabase mongoDatabase;

	@Autowired
	public MongoDb(final MongoDatabase mongoDatabase) {
		this.mongoDatabase = mongoDatabase;
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
