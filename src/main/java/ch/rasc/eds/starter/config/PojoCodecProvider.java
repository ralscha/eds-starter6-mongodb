package ch.rasc.eds.starter.config;

import org.bson.codecs.Codec;
import org.bson.codecs.configuration.CodecProvider;
import org.bson.codecs.configuration.CodecRegistry;

import ch.rasc.eds.starter.entity.PersistentLogin;
import ch.rasc.eds.starter.entity.PersistentLoginCodec;
import ch.rasc.eds.starter.entity.UUIDStringGenerator;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.entity.UserCodec;

public final class PojoCodecProvider implements CodecProvider {
	private final UUIDStringGenerator uUIDStringGenerator;

	public PojoCodecProvider() {
		this(new UUIDStringGenerator());
	}

	public PojoCodecProvider(final UUIDStringGenerator uUIDStringGenerator) {
		this.uUIDStringGenerator = uUIDStringGenerator;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T> Codec<T> get(final Class<T> clazz, final CodecRegistry registry) {
		if (clazz.equals(PersistentLogin.class)) {
			return (Codec<T>) new PersistentLoginCodec();
		}
		if (clazz.equals(User.class)) {
			return (Codec<T>) new UserCodec(this.uUIDStringGenerator);
		}
		return null;
	}
}
