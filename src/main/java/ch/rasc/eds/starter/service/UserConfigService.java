package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_MODIFY;
import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_READ;

import java.util.List;
import java.util.Locale;

import javax.validation.Validator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import ch.ralscha.extdirectspring.annotation.ExtDirectMethod;
import ch.ralscha.extdirectspring.bean.ExtDirectStoreResult;
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

	private final MongoTemplate mongoTemplate;

	private final Validator validator;

	private final MessageSource messageSource;

	@Autowired
	public UserConfigService(MongoTemplate mongoTemplate, Validator validator,
			PasswordEncoder passwordEncoder, MessageSource messageSource) {
		this.mongoTemplate = mongoTemplate;
		this.messageSource = messageSource;
		this.validator = validator;
		this.passwordEncoder = passwordEncoder;
	}

	@ExtDirectMethod(STORE_READ)
	public ExtDirectStoreResult<UserSettings> readSettings(
			@AuthenticationPrincipal MongoUserDetails userDetails) {
		UserSettings userSettings = new UserSettings(
				userDetails.getUser(this.mongoTemplate));
		return new ExtDirectStoreResult<>(userSettings);
	}

	@ExtDirectMethod
	public String enable2f(@AuthenticationPrincipal MongoUserDetails userDetails) {
		String randomSecret = TotpAuthUtil.randomSecret();

		this.mongoTemplate.updateFirst(
				Query.query(Criteria.where(CUser.id).is(userDetails.getUserDbId())),
				Update.update(CUser.secret, randomSecret), User.class);

		return randomSecret;
	}

	@ExtDirectMethod
	public void disable2f(@AuthenticationPrincipal MongoUserDetails userDetails) {
		this.mongoTemplate.updateFirst(
				Query.query(Criteria.where(CUser.id).is(userDetails.getUserDbId())),
				Update.update(CUser.secret, null), User.class);
	}

	@ExtDirectMethod(STORE_MODIFY)
	public ValidationMessagesResult<UserSettings> updateSettings(
			UserSettings modifiedUserSettings,
			@AuthenticationPrincipal MongoUserDetails userDetails, Locale locale) {

		List<ValidationMessages> validations = ValidationUtil
				.validateEntity(this.validator, modifiedUserSettings);
		User user = userDetails.getUser(this.mongoTemplate);

		if (StringUtils.hasText(modifiedUserSettings.getNewPassword())
				&& validations.isEmpty()) {
			if (this.passwordEncoder.matches(modifiedUserSettings.getCurrentPassword(),
					user.getPasswordHash())) {
				if (modifiedUserSettings.getNewPassword()
						.equals(modifiedUserSettings.getNewPasswordRetype())) {
					user.setPasswordHash(this.passwordEncoder
							.encode(modifiedUserSettings.getNewPassword()));
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

		if (!isEmailUnique(user.getId(), modifiedUserSettings.getEmail())) {
			ValidationMessages validationError = new ValidationMessages();
			validationError.setField(CUser.email);
			validationError.setMessage(
					this.messageSource.getMessage("user_emailtaken", null, locale));
			validations.add(validationError);
		}

		if (validations.isEmpty()) {
			user.setLastName(modifiedUserSettings.getLastName());
			user.setFirstName(modifiedUserSettings.getFirstName());
			user.setEmail(modifiedUserSettings.getEmail());
			user.setLocale(modifiedUserSettings.getLocale());
		}

		this.mongoTemplate.save(user);

		return new ValidationMessagesResult<>(modifiedUserSettings, validations);
	}

	private boolean isEmailUnique(String userId, String email) {
		Query query = Query
				.query(Criteria.where(CUser.email).regex("^" + email + "$", "i"));
		query.addCriteria(Criteria.where(CUser.id).ne(userId));

		return !this.mongoTemplate.exists(query, User.class);
	}

	@ExtDirectMethod(STORE_READ)
	public List<PersistentLogin> readPersistentLogins(
			@AuthenticationPrincipal MongoUserDetails userDetails) {

		List<PersistentLogin> persistentLogins = this.mongoTemplate.find(Query.query(
				Criteria.where(CPersistentLogin.userId).is(userDetails.getUserDbId())),
				PersistentLogin.class);

		persistentLogins.forEach(p -> {
			String ua = p.getUserAgent();
			if (StringUtils.hasText(ua)) {
				UserAgent userAgent = UserAgent.parseUserAgentString(ua);
				p.setUserAgentName(userAgent.getBrowser().getGroup().getName());
				p.setUserAgentVersion(userAgent.getBrowserVersion().getMajorVersion());
				p.setOperatingSystem(userAgent.getOperatingSystem().getName());
			}
		});

		return persistentLogins;
	}

	@ExtDirectMethod(STORE_MODIFY)
	public void destroyPersistentLogin(String series,
			@AuthenticationPrincipal MongoUserDetails userDetails) {
		this.mongoTemplate.remove(
				Query.query(Criteria.where(CPersistentLogin.series).is(series)
						.and(CPersistentLogin.userId).is(userDetails.getUserDbId())),
				PersistentLogin.class);
	}

}
