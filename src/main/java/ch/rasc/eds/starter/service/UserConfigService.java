package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_MODIFY;
import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_READ;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.validation.Validator;

import org.bson.conversions.Bson;
import org.springframework.context.MessageSource;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;

import ch.ralscha.extdirectspring.annotation.ExtDirectMethod;
import ch.ralscha.extdirectspring.bean.ExtDirectStoreResult;
import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.config.security.MongoUserDetails;
import ch.rasc.eds.starter.config.security.RequireAnyAuthority;
import ch.rasc.eds.starter.dto.UserSettings;
import ch.rasc.eds.starter.entity.CPersistentLogin;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.PersistentLogin;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.util.TotpAuthUtil;
import ch.rasc.eds.starter.util.ValidationMessages;
import ch.rasc.eds.starter.util.ValidationMessagesResult;
import ch.rasc.eds.starter.util.ValidationUtil;
import eu.bitwalker.useragentutils.UserAgent;

@Service
@RequireAnyAuthority
public class UserConfigService {

	private final PasswordEncoder passwordEncoder;

	private final MongoDb mongoDb;

	private final Validator validator;

	private final MessageSource messageSource;

	public UserConfigService(MongoDb mongoDb, Validator validator,
			PasswordEncoder passwordEncoder, MessageSource messageSource) {
		this.mongoDb = mongoDb;
		this.messageSource = messageSource;
		this.validator = validator;
		this.passwordEncoder = passwordEncoder;
	}

	@ExtDirectMethod(STORE_READ)
	public ExtDirectStoreResult<UserSettings> readSettings(
			@AuthenticationPrincipal MongoUserDetails userDetails) {
		UserSettings userSettings = new UserSettings(userDetails.getUser(this.mongoDb));
		return new ExtDirectStoreResult<>(userSettings);
	}

	@ExtDirectMethod
	public String enable2f(@AuthenticationPrincipal MongoUserDetails userDetails) {
		String randomSecret = TotpAuthUtil.randomSecret();

		this.mongoDb.getCollection(User.class).updateOne(
				Filters.eq(CUser.id, userDetails.getUserDbId()),
				Updates.set(CUser.secret, randomSecret));

		return randomSecret;
	}

	@ExtDirectMethod
	public void disable2f(@AuthenticationPrincipal MongoUserDetails userDetails) {
		this.mongoDb.getCollection(User.class).updateOne(
				Filters.eq(CUser.id, userDetails.getUserDbId()),
				Updates.unset(CUser.secret));
	}

	@ExtDirectMethod(STORE_MODIFY)
	public ValidationMessagesResult<UserSettings> updateSettings(
			UserSettings modifiedUserSettings,
			@AuthenticationPrincipal MongoUserDetails userDetails, Locale locale) {

		List<ValidationMessages> validations = ValidationUtil
				.validateEntity(this.validator, modifiedUserSettings);
		User user = userDetails.getUser(this.mongoDb);
		List<Bson> updates = new ArrayList<>();

		if (StringUtils.hasText(modifiedUserSettings.getNewPassword())
				&& validations.isEmpty()) {
			if (this.passwordEncoder.matches(modifiedUserSettings.getCurrentPassword(),
					user.getPasswordHash())) {
				if (modifiedUserSettings.getNewPassword()
						.equals(modifiedUserSettings.getNewPasswordRetype())) {
					user.setPasswordHash(this.passwordEncoder
							.encode(modifiedUserSettings.getNewPassword()));
					updates.add(Updates.set(CUser.passwordHash, user.getPasswordHash()));
				}
				else {
					for (String field : new String[] { "newPassword",
							"newPasswordRetype" }) {
						ValidationMessages error = new ValidationMessages();
						error.setField(field);
						error.setMessage(this.messageSource
								.getMessage("userconfig_pwdonotmatch", null, locale));
						validations.add(error);
					}
				}
			}
			else {
				ValidationMessages error = new ValidationMessages();
				error.setField("currentPassword");
				error.setMessage(this.messageSource.getMessage("userconfig_wrongpassword",
						null, locale));
				validations.add(error);
			}
		}

		if (!UserService.isEmailUnique(this.mongoDb, user.getId(),
				modifiedUserSettings.getEmail())) {
			ValidationMessages validationError = new ValidationMessages();
			validationError.setField(CUser.email);
			validationError.setMessage(
					this.messageSource.getMessage("user_emailtaken", null, locale));
			validations.add(validationError);
		}

		if (!UserService.isLoginNameUnique(this.mongoDb, user.getId(),
				modifiedUserSettings.getLoginName())) {
			ValidationMessages validationError = new ValidationMessages();
			validationError.setField(CUser.loginName);
			validationError.setMessage(
					this.messageSource.getMessage("user_loginnametaken", null, locale));
			validations.add(validationError);
		}

		if (validations.isEmpty()) {
			user.setLoginName(modifiedUserSettings.getLoginName());
			user.setLastName(modifiedUserSettings.getLastName());
			user.setFirstName(modifiedUserSettings.getFirstName());
			user.setEmail(modifiedUserSettings.getEmail());
			user.setLocale(modifiedUserSettings.getLocale());

			updates.add(Updates.set(CUser.loginName, user.getLoginName()));
			updates.add(Updates.set(CUser.lastName, user.getLastName()));
			updates.add(Updates.set(CUser.firstName, user.getFirstName()));
			updates.add(Updates.set(CUser.email, user.getEmail()));
			updates.add(Updates.set(CUser.locale, user.getLocale()));
		}

		if (!updates.isEmpty()) {
			this.mongoDb.getCollection(User.class).updateOne(
					Filters.eq(CUser.id, user.getId()), Updates.combine(updates));
		}

		return new ValidationMessagesResult<>(modifiedUserSettings, validations);
	}

	@ExtDirectMethod(STORE_READ)
	public List<PersistentLogin> readPersistentLogins(
			@AuthenticationPrincipal MongoUserDetails userDetails) {

		return StreamSupport
				.stream(this.mongoDb.getCollection(PersistentLogin.class)
						.find(Filters.eq(CPersistentLogin.userId,
								userDetails.getUserDbId()))
						.spliterator(), false)
				.peek(p -> {
					String ua = p.getUserAgent();
					if (StringUtils.hasText(ua)) {
						UserAgent userAgent = UserAgent.parseUserAgentString(ua);
						p.setUserAgentName(userAgent.getBrowser().getGroup().getName());
						p.setUserAgentVersion(
								userAgent.getBrowserVersion().getMajorVersion());
						p.setOperatingSystem(userAgent.getOperatingSystem().getName());
					}
				}).collect(Collectors.toList());

	}

	@ExtDirectMethod(STORE_MODIFY)
	public void destroyPersistentLogin(String series,
			@AuthenticationPrincipal MongoUserDetails userDetails) {
		this.mongoDb.getCollection(PersistentLogin.class)
				.deleteOne(Filters.and(Filters.eq(CPersistentLogin.series, series),
						Filters.eq(CPersistentLogin.userId, userDetails.getUserDbId())));
	}

}
