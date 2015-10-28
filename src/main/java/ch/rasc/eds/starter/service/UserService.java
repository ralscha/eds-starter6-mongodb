package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_MODIFY;
import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_READ;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.validation.Validator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import ch.ralscha.extdirectspring.annotation.ExtDirectMethod;
import ch.ralscha.extdirectspring.bean.ExtDirectStoreReadRequest;
import ch.ralscha.extdirectspring.bean.ExtDirectStoreResult;
import ch.ralscha.extdirectspring.filter.StringFilter;
import ch.rasc.eds.starter.config.security.RequireAdminAuthority;
import ch.rasc.eds.starter.entity.Authority;
import ch.rasc.eds.starter.entity.CPersistentLogin;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.PersistentLogin;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.util.RepositoryUtil;
import ch.rasc.eds.starter.util.ValidationMessages;
import ch.rasc.eds.starter.util.ValidationMessagesResult;
import ch.rasc.eds.starter.util.ValidationUtil;
import de.danielbechler.diff.ObjectDiffer;
import de.danielbechler.diff.ObjectDifferBuilder;
import de.danielbechler.diff.node.DiffNode;
import de.danielbechler.diff.node.DiffNode.State;

@Service
@RequireAdminAuthority
public class UserService {

	private final MessageSource messageSource;

	private final Validator validator;

	private final MongoTemplate mongoTemplate;

	private final MailService mailService;

	@Autowired
	public UserService(MongoTemplate mongoTemplate, Validator validator,
			MessageSource messageSource, MailService mailService) {
		this.mongoTemplate = mongoTemplate;
		this.messageSource = messageSource;
		this.validator = validator;
		this.mailService = mailService;
	}

	@ExtDirectMethod(STORE_READ)
	public ExtDirectStoreResult<User> read(ExtDirectStoreReadRequest request) {

		Criteria criteria;
		if (!request.getFilters().isEmpty()) {
			StringFilter filter = (StringFilter) request.getFilters().iterator().next();
			Criteria or = new Criteria().orOperator(
					Criteria.where(CUser.lastName).regex(filter.getValue(), "i"),
					Criteria.where(CUser.firstName).regex(filter.getValue(), "i"),
					Criteria.where(CUser.email).regex(filter.getValue(), "i"));
			criteria = new Criteria().andOperator(Criteria.where(CUser.deleted).is(false),
					or);
		}
		else {
			criteria = Criteria.where(CUser.deleted).is(false);
		}

		Query query = Query.query(criteria);
		long total = this.mongoTemplate.count(query, User.class);

		List<User> users = this.mongoTemplate
				.find(query.with(RepositoryUtil.createPageable(request)), User.class);

		users.forEach(u -> u.setTwoFactorAuth(StringUtils.hasText(u.getSecret())));

		return new ExtDirectStoreResult<>(total, users);
	}

	@ExtDirectMethod(STORE_MODIFY)
	public ExtDirectStoreResult<User> destroy(User destroyUser) {
		ExtDirectStoreResult<User> result = new ExtDirectStoreResult<>();
		if (!isLastAdmin(destroyUser.getId())) {
			this.mongoTemplate.updateFirst(
					Query.query(Criteria.where(CUser.id).is(destroyUser.getId())),
					Update.update(CUser.deleted, true), User.class);
			result.setSuccess(Boolean.TRUE);

			deletePersistentLogins(destroyUser.getId());
		}
		else {
			result.setSuccess(Boolean.FALSE);
		}
		return result;
	}

	private void deletePersistentLogins(String userId) {
		this.mongoTemplate.remove(
				Query.query(Criteria.where(CPersistentLogin.userId).is(userId)),
				PersistentLogin.class);
	}

	@ExtDirectMethod(STORE_MODIFY)
	public ValidationMessagesResult<User> update(User updatedEntity, Locale locale) {

		User user = this.mongoTemplate.findById(updatedEntity.getId(), User.class);
		List<ValidationMessages> violations = new ArrayList<>();

		if (user != null) {
			updatedEntity.setPasswordHash(user.getPasswordHash());
			updatedEntity.setSecret(user.getSecret());
			updatedEntity.setPasswordResetToken(user.getPasswordResetToken());
			updatedEntity.setPasswordResetTokenValidUntil(
					user.getPasswordResetTokenValidUntil());
			updatedEntity.setLastAccess(user.getLastAccess());
			updatedEntity.setLockedOutUntil(user.getLockedOutUntil());
			updatedEntity.setFailedLogins(user.getFailedLogins());

			violations.addAll(checkIfLastAdmin(updatedEntity, locale, user));
		}

		violations.addAll(validateEntity(updatedEntity, locale));

		if (violations.isEmpty()) {
			this.mongoTemplate.save(updatedEntity);

			if (!updatedEntity.isEnabled()) {
				deletePersistentLogins(updatedEntity.getId());
			}

			return new ValidationMessagesResult<>(updatedEntity);
		}

		ValidationMessagesResult<User> result = new ValidationMessagesResult<>(
				updatedEntity);
		result.setValidations(violations);
		return result;
	}

	private List<ValidationMessages> checkIfLastAdmin(User updatedEntity, Locale locale,
			User dbUser) {

		List<ValidationMessages> validationErrors = new ArrayList<>();

		if (dbUser != null && (!updatedEntity.isEnabled()
				|| !updatedEntity.getAuthorities().contains(Authority.ADMIN.name()))) {
			if (isLastAdmin(updatedEntity.getId())) {

				ObjectDiffer objectDiffer = ObjectDifferBuilder.startBuilding()
						.filtering().returnNodesWithState(State.UNTOUCHED).and().build();
				DiffNode diff = objectDiffer.compare(updatedEntity, dbUser);

				DiffNode diffNode = diff.getChild(CUser.enabled);
				if (!diffNode.isUntouched()) {
					updatedEntity.setEnabled(dbUser.isEnabled());

					ValidationMessages validationError = new ValidationMessages();
					validationError.setField(CUser.enabled);
					validationError.setMessage(this.messageSource
							.getMessage("user_lastadmin_error", null, locale));
					validationErrors.add(validationError);
				}

				diffNode = diff.getChild(CUser.authorities);
				if (!diffNode.isUntouched()) {
					updatedEntity.setAuthorities(dbUser.getAuthorities());

					ValidationMessages validationError = new ValidationMessages();
					validationError.setField(CUser.authorities);
					validationError.setMessage(this.messageSource
							.getMessage("user_lastadmin_error", null, locale));
					validationErrors.add(validationError);
				}

			}
		}

		return validationErrors;
	}

	private List<ValidationMessages> validateEntity(User user, Locale locale) {
		List<ValidationMessages> validations = ValidationUtil
				.validateEntity(this.validator, user);

		if (!isEmailUnique(user.getId(), user.getEmail())) {
			ValidationMessages validationError = new ValidationMessages();
			validationError.setField(CUser.email);
			validationError.setMessage(
					this.messageSource.getMessage("user_emailtaken", null, locale));
			validations.add(validationError);
		}

		return validations;
	}

	private boolean isLastAdmin(String id) {
		Query query = Query.query(Criteria.where(CUser.id).ne(id).and(CUser.deleted)
				.is(false).and(CUser.authorities).is(Authority.ADMIN.name())
				.and(CUser.enabled).is(true));
		return !this.mongoTemplate.exists(query, User.class);
	}

	private boolean isEmailUnique(String userId, String email) {
		if (StringUtils.hasText(email)) {

			Query query = Query
					.query(Criteria.where(CUser.email).regex("^" + email + "$", "i"));

			if (userId != null) {
				query.addCriteria(Criteria.where(CUser.id).ne(userId));
			}

			return !this.mongoTemplate.exists(query, User.class);
		}

		return true;
	}

	@ExtDirectMethod(STORE_READ)
	public List<Map<String, String>> readAuthorities() {
		return Arrays.stream(Authority.values())
				.map(r -> Collections.singletonMap("name", r.name()))
				.collect(Collectors.toList());
	}

	@ExtDirectMethod
	public void unlock(String userId) {
		this.mongoTemplate.updateFirst(Query.query(Criteria.where(CUser.id).is(userId)),
				Update.update(CUser.lockedOutUntil, null).set(CUser.failedLogins, 0),
				User.class);
	}

	@ExtDirectMethod
	public void disableTwoFactorAuth(String userId) {
		this.mongoTemplate.updateFirst(Query.query(Criteria.where(CUser.id).is(userId)),
				Update.update(CUser.secret, null), User.class);
	}

	@ExtDirectMethod
	public void sendPassordResetEmail(String userId) {
		String token = UUID.randomUUID().toString();
		User user = this.mongoTemplate.findAndModify(
				Query.query(Criteria.where(CUser.id).is(userId)), Update
						.update(CUser.passwordResetTokenValidUntil,
								Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusHours(4)
										.toInstant()))
						.set(CUser.passwordResetToken, token),
				FindAndModifyOptions.options().returnNew(true), User.class);

		this.mailService.sendPasswortResetEmail(user);
	}

}
