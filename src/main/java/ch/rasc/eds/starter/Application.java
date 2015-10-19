package ch.rasc.eds.starter;

import java.lang.invoke.MethodHandles;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.web.SpringDataWebAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.autoconfigure.mustache.MustacheAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import ch.ralscha.extdirectspring.ExtDirectSpring;
import ch.ralscha.extdirectspring.controller.ApiController;

@Configuration
@ComponentScan(basePackageClasses = { ExtDirectSpring.class, Application.class },
		excludeFilters = { @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
				value = ApiController.class) })
@EnableAutoConfiguration(exclude = { MustacheAutoConfiguration.class,
		MongoAutoConfiguration.class, SpringDataWebAutoConfiguration.class })
@EnableAsync
@EnableScheduling
public class Application {

	public static final Logger logger = LoggerFactory
			.getLogger(MethodHandles.lookup().lookupClass());

	public static void main(String[] args) {
		// -Dspring.profiles.active=development
		SpringApplication.run(Application.class, args);
	}

}
