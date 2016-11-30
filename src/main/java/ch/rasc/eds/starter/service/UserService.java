package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_MODIFY;
import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.STORE_READ;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import javax.validation.Validator;

import org.bson.conversions.Bson;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.model.Updates;

import ch.ralscha.extdirectspring.annotation.ExtDirectMethod;
import ch.ralscha.extdirectspring.bean.ExtDirectStoreReadRequest;
import ch.ralscha.extdirectspring.bean.ExtDirectStoreResult;
import ch.ralscha.extdirectspring.filter.StringFilter;
import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.config.security.RequireAdminAuthority;
import ch.rasc.eds.starter.entity.Authority;
import ch.rasc.eds.starter.entity.CPersistentLogin;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.PersistentLogin;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.util.QueryUtil;
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

	private final MongoDb mongoDb;

	private final MailService mailService;

	public UserService(MongoDb mongoDb, Validator validator, MessageSource messageSource,
			MailService mailService) {
		this.mongoDb = mongoDb;
		this.messageSource = messageSource;
		this.validator = validator;
		this.mailService = mailService;
	}

	@ExtDirectMethod(STORE_READ)
	public ExtDirectStoreResult<User> read(ExtDirectStoreReadRequest request) {

		List<Bson> andFilters = new ArrayList<>();
		StringFilter filter = request.getFirstFilterForField("filter");
		if (filter != null) {
			List<Bson> orFilters = new ArrayList<>();
			orFilters.add(Filters.regex(CUser.loginName, filter.getValue(), "i"));
			orFilters.add(Filters.regex(CUser.lastName, filter.getValue(), "i"));
			orFilters.add(Filters.regex(CUser.firstName, filter.getValue(), "i"));
			orFilters.add(Filters.regex(CUser.email, filter.getValue(), "i"));

			andFilters.add(Filters.or(orFilters));
		}
		andFilters.add(Filters.eq(CUser.deleted, false));

		long total = this.mongoDb.getCollection(User.class)
				.count(Filters.and(andFilters));

		FindIterable<User> find = this.mongoDb.getCollection(User.class)
				.find(Filters.and(andFilters));
		find.sort(Sorts.orderBy(QueryUtil.getSorts(request)));
		find.skip(request.getStart());
		find.limit(request.getLimit());

		return new ExtDirectStoreResult<>(total, QueryUtil.toList(find));
	}

	@ExtDirectMethod(STORE_MODIFY)
	public ExtDirectStoreResult<User> destroy(User destroyUser) {
		ExtDirectStoreResult<User> result = new ExtDirectStoreResult<>();
		if (!isLastAdmin(destroyUser.getId())) {
			this.mongoDb.getCollection(User.class).updateOne(
					Filters.eq(CUser.id, destroyUser.getId()),
					Updates.combine(Updates.set(CUser.deleted, true),
							Updates.set(CUser.enabled, false),
							Updates.unset(CUser.loginName), Updates.unset(CUser.email),
							Updates.unset(CUser.passwordHash)));
			result.setSuccess(Boolean.TRUE);

			deletePersistentLogins(destroyUser.getId());
		}
		else {
			result.setSuccess(Boolean.FALSE);
		}
		return result;
	}

	private void deletePersistentLogins(String userId) {
		this.mongoDb.getCollection(PersistentLogin.class)
				.deleteMany(Filters.eq(CPersistentLogin.userId, userId));
	}

	@ExtDirectMethod(STORE_MODIFY)
	public ValidationMessagesResult<User> update(User updatedEntity, Locale locale) {
		List<ValidationMessages> violations = validateEntity(updatedEntity, locale);
		violations.addAll(checkIfLastAdmin(updatedEntity, locale));

		if (violations.isEmpty()) {

			List<Bson> updates = new ArrayList<>();
			updates.add(Updates.set(CUser.loginName, updatedEntity.getLoginName()));
			updates.add(Updates.set(CUser.email, updatedEntity.getEmail()));
			updates.add(Updates.set(CUser.firstName, updatedEntity.getFirstName()));
			updates.add(Updates.set(CUser.lastName, updatedEntity.getLastName()));
			updates.add(Updates.set(CUser.locale, updatedEntity.getLocale()));
			updates.add(Updates.set(CUser.enabled, updatedEntity.isEnabled()));
			if (updatedEntity.getAuthorities() != null
					&& !updatedEntity.getAuthorities().isEmpty()) {
				updates.add(
						Updates.set(CUser.authorities, updatedEntity.getAuthorities()));
			}
			else {
				updates.add(Updates.unset(CUser.authorities));
			}
			updates.add(Updates.setOnInsert(CUser.deleted, false));

			this.mongoDb.getCollection(User.class).updateOne(
					Filters.eq(CUser.id, updatedEntity.getId()), Updates.combine(updates),
					new UpdateOptions().upsert(true));

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

	private List<ValidationMessages> checkIfLastAdmin(User updatedEntity, Locale locale) {
		User dbUser = this.mongoDb.getCollection(User.class)
				.find(Filters.eq(CUser.id, updatedEntity.getId())).first();

		List<ValidationMessages> validationErrors = new ArrayList<>();

		if (dbUser != null && (!updatedEntity.isEnabled()
				|| updatedEntity.getAuthorities() == null
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

		if (!isEmailUnique(this.mongoDb, user.getId(), user.getEmail())) {
			ValidationMessages validationError = new ValidationMessages();
			validationError.setField(CUser.email);
			validationError.setMessage(
					this.messageSource.getMessage("user_emailtaken", null, locale));
			validations.add(validationError);
		}

		if (!isLoginNameUnique(this.mongoDb, user.getId(), user.getLoginName())) {
			ValidationMessages validationError = new ValidationMessages();
			validationError.setField(CUser.loginName);
			validationError.setMessage(
					this.messageSource.getMessage("user_loginnametaken", null, locale));
			validations.add(validationError);
		}

		return validations;
	}

	private boolean isLastAdmin(String id) {

		long count = this.mongoDb.getCollection(User.class)
				.count(Filters.and(Filters.ne(CUser.id, id),
						Filters.eq(CUser.deleted, false),
						Filters.eq(CUser.authorities, Authority.ADMIN.name()),
						Filters.eq(CUser.enabled, true)));
		return count == 0;
	}

	public static boolean isEmailUnique(MongoDb mongoDb, String userId, String email) {
		if (StringUtils.hasText(email)) {
			long count;
			if (userId != null) {
				count = mongoDb.getCollection(User.class)
						.count(Filters.and(
								Filters.regex(CUser.email, "^" + email + "$", "i"),
								Filters.ne(CUser.id, userId)));
			}
			else {
				count = mongoDb.getCollection(User.class)
						.count(Filters.regex(CUser.email, "^" + email + "$", "i"));
			}

			return count == 0;
		}

		return true;
	}

	public static boolean isLoginNameUnique(MongoDb mongoDb, String userId,
			String loginName) {
		if (StringUtils.hasText(loginName)) {
			long count;
			if (userId != null) {
				count = mongoDb.getCollection(User.class)
						.count(Filters.and(Filters.regex(CUser.loginName,
								"^" + loginName + "$", "i"),
								Filters.ne(CUser.id, userId)));
			}
			else {
				count = mongoDb.getCollection(User.class).count(
						Filters.regex(CUser.loginName, "^" + loginName + "$", "i"));

			}
			return count == 0;
		}

		return false;
	}

	@ExtDirectMethod
	public void unlock(String userId) {
		this.mongoDb.getCollection(User.class).updateOne(Filters.eq(CUser.id, userId),
				Updates.combine(Updates.unset(CUser.lockedOutUntil),
						Updates.set(CUser.failedLogins, 0)));
	}

	@ExtDirectMethod
	public void disableTwoFactorAuth(String userId) {
		this.mongoDb.getCollection(User.class).updateOne(Filters.eq(CUser.id, userId),
				Updates.unset(CUser.secret));
	}

	@ExtDirectMethod
	public void sendPassordResetEmail(String userId) {
		String token = UUID.randomUUID().toString();

		User user = this.mongoDb.getCollection(User.class).findOneAndUpdate(
				Filters.eq(CUser.id, userId),
				Updates.combine(
						Updates.set(CUser.passwordResetTokenValidUntil,
								Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusHours(4)
										.toInstant())),
						Updates.set(CUser.passwordResetToken, token)),
				new FindOneAndUpdateOptions().returnDocument(ReturnDocument.AFTER));

		this.mailService.sendPasswortResetEmail(user);
	}

}
