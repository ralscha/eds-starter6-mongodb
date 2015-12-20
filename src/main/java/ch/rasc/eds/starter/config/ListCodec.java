package ch.rasc.eds.starter.config;

import java.util.List;

import org.bson.BsonReader;
import org.bson.BsonWriter;
import org.bson.codecs.Codec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.bson.codecs.configuration.CodecProvider;
import org.bson.codecs.configuration.CodecRegistry;

@SuppressWarnings({ "unchecked", "rawtypes" })
public final class ListCodec implements Codec<List> {
	private final CodecRegistry codecRegistry;

	public static class Provider implements CodecProvider {

		@Override
		public <T> Codec<T> get(Class<T> clazz, CodecRegistry registry) {
			if (List.class.isAssignableFrom(clazz)) {
				return (Codec<T>) new ListCodec(registry);
			}
			return null;
		}
	}

	public ListCodec(CodecRegistry codecRegistry) {
		this.codecRegistry = codecRegistry;
	}

	@Override
	public void encode(BsonWriter writer, List value, EncoderContext encoderContext) {
		if (value != null && !value.isEmpty()) {
			writer.writeStartArray();
			for (Object a : value) {
				if (a != null) {
					Codec codec = this.codecRegistry.get(a.getClass());
					encoderContext.encodeWithChildContext(codec, writer, a);
				}
				else {
					writer.writeNull();
				}
			}
			writer.writeEndArray();
		}
		else {
			writer.writeNull();
		}
	}

	@Override
	public List decode(BsonReader reader, DecoderContext decoderContext) {
		throw new UnsupportedOperationException("this codec is only used for encoding");
	}

	@Override
	public Class<List> getEncoderClass() {
		return List.class;
	}
}
