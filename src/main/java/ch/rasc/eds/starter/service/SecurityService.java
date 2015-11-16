package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.POLL;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.bson.conversions.Bson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestParam;

import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Updates;

import ch.ralscha.extdirectspring.annotation.ExtDirectMethod;
import ch.ralscha.extdirectspring.annotation.ExtDirectMethodType;
import ch.ralscha.extdirectspring.bean.ExtDirectFormPostResult;
import ch.rasc.eds.starter.Application;
import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.config.security.MongoUserDetails;
import ch.rasc.eds.starter.config.security.RequireAdminAuthority;
import ch.rasc.eds.starter.config.security.RequireAnyAuthority;
import ch.rasc.eds.starter.dto.UserDetailDto;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.util.TotpAuthUtil;

@Service
public class SecurityService {
	public static final String AUTH_USER = "authUser";

	private final MongoDb mongoDb;

	private final PasswordEncoder passwordEncoder;

	private final MailService mailService;

	private final ApplicationEventPublisher applicationEventPublisher;

	@Autowired
	public SecurityService(MongoDb mongoDb, PasswordEncoder passwordEncoder,
			MailService mailService,
			ApplicationEventPublisher applicationEventPublisher) {
		this.mongoDb = mongoDb;
		this.passwordEncoder = passwordEncoder;
		this.mailService = mailService;
		this.applicationEventPublisher = applicationEventPublisher;
	}

	@ExtDirectMethod
	public UserDetailDto getAuthUser(
			@AuthenticationPrincipal MongoUserDetails userDetails) {

		if (userDetails != null) {
			User user = userDetails.getUser(this.mongoDb);
			UserDetailDto userDetailDto = new UserDetailDto(userDetails, user);

			if (!userDetails.isPreAuth()) {
				// this.mongoDb.updateFirst(
				// Query.query(
				// Criteria.where(CUser.id).is(userDetails.getUserDbId())),
				// Update.update(CUser.lastAccess, new Date()), User.class);

				mongoDb.getCollection(User.class).updateOne(
						Filters.eq(CUser.id, userDetails.getUserDbId()),
						Updates.set(CUser.lastAccess, new Date()));

			}

			return userDetailDto;
		}

		return null;
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	@PreAuthorize("hasAuthority('PRE_AUTH')")
	public ExtDirectFormPostResult signin2fa(HttpServletRequest request,
			@AuthenticationPrincipal MongoUserDetails userDetails,
			@RequestParam("code") int code) {

		User user = userDetails.getUser(this.mongoDb);
		if (user != null) {
			if (TotpAuthUtil.verifyCode(user.getSecret(), code, 3)) {

				mongoDb.getCollection(User.class).updateOne(
						Filters.eq(CUser.id, userDetails.getUserDbId()),
						Updates.set(CUser.lastAccess, new Date()));

				// this.mongoDb.updateFirst(
				// Query.query(
				// Criteria.where(CUser.id).is(userDetails.getUserDbId())),
				// Update.update(CUser.lastAccess, new Date()), User.class);

				userDetails.grantAuthorities();

				Authentication newAuth = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(newAuth);

				ExtDirectFormPostResult result = new ExtDirectFormPostResult();
				result.addResultProperty(AUTH_USER, new UserDetailDto(userDetails, user));
				return result;
			}

			BadCredentialsException excp = new BadCredentialsException(
					"Bad verification code");
			AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
					SecurityContextHolder.getContext().getAuthentication(), excp);
			this.applicationEventPublisher.publishEvent(event);

			user = userDetails.getUser(this.mongoDb);
			if (user.getLockedOutUntil() != null) {
				HttpSession session = request.getSession(false);
				if (session != null) {
					Application.logger.debug("Invalidating session: " + session.getId());
					session.invalidate();
				}
				SecurityContext context = SecurityContextHolder.getContext();
				context.setAuthentication(null);
				SecurityContextHolder.clearContext();
			}
		}

		return new ExtDirectFormPostResult(false);
	}

	@ExtDirectMethod
	@RequireAnyAuthority
	public void enableScreenLock(@AuthenticationPrincipal MongoUserDetails userDetails) {
		userDetails.setScreenLocked(true);
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	@RequireAnyAuthority
	public ExtDirectFormPostResult disableScreenLock(
			@AuthenticationPrincipal MongoUserDetails userDetails,
			@RequestParam("password") String password) {

		User user = mongoDb.getCollection(User.class)
				.find(Filters.eq(CUser.id, userDetails.getUserDbId()))
				.projection(Projections.include(CUser.passwordHash)).first();

		// Query query =
		// Query.query(Criteria.where(CUser.id).is(userDetails.getUserDbId()));
		// query.fields().include(CUser.passwordHash);
		// User user = this.mongoDb.findOne(query, User.class);
		boolean matches = this.passwordEncoder.matches(password, user.getPasswordHash());
		userDetails.setScreenLocked(!matches);
		ExtDirectFormPostResult result = new ExtDirectFormPostResult(matches);

		return result;
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	public ExtDirectFormPostResult resetRequest(@RequestParam("email") String email) {

		String token = UUID.randomUUID().toString();
		
		
		User user = mongoDb.getCollection(User.class).findOneAndUpdate(
				Filters.and(Filters.eq(CUser.email, email), Filters.eq(CUser.deleted, false)),
				Updates.combine(
				Updates.set(CUser.passwordResetTokenValidUntil, Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusHours(4).toInstant())),
				Updates.set(CUser.passwordResetToken, token)
				),
				new FindOneAndUpdateOptions()
						.returnDocument(ReturnDocument.AFTER).upsert(false));
		
//		User user = this.mongoDb.findAndModify(
//				Query.query(Criteria.where(CUser.email).is(email).and(CUser.deleted)
//						.is(false)),
//				Update.update(CUser.passwordResetTokenValidUntil,
//						Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusHours(4)
//								.toInstant()))
//						.set(CUser.passwordResetToken, token),
//				FindAndModifyOptions.options().returnNew(true).upsert(false), User.class);

		if (user != null) {
			this.mailService.sendPasswortResetEmail(user);
		}

		return new ExtDirectFormPostResult();
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	public ExtDirectFormPostResult reset(@RequestParam("newPassword") String newPassword,
			@RequestParam("newPasswordRetype") String newPasswordRetype,
			@RequestParam("token") String token) {

		if (StringUtils.hasText(token) && StringUtils.hasText(newPassword)
				&& StringUtils.hasText(newPasswordRetype)
				&& newPassword.equals(newPasswordRetype)) {
			String decodedToken = new String(Base64.getUrlDecoder().decode(token));
			User user = mongoDb.getCollection(User.class).find(Filters.and(Filters.eq(CUser.passwordResetToken, decodedToken), Filters.eq(CUser.deleted, false),
					Filters.eq(CUser.enabled, true))).first();
//			User user = this.mongoDb.findOne(
//					Query.query(Criteria.where(CUser.passwordResetToken).is(decodedToken)
//							.and(CUser.deleted).is(false).and(CUser.enabled).is(true)),
//					User.class);

			if (user != null && user.getPasswordResetTokenValidUntil() != null) {

				ExtDirectFormPostResult result;
				List<Bson> updates = new ArrayList<>();
				
				if (user.getPasswordResetTokenValidUntil().after(new Date())) {
					user.setPasswordHash(this.passwordEncoder.encode(newPassword));
					user.setSecret(null);
					updates.add(Updates.unset(CUser.secret));
					updates.add(Updates.set(CUser.passwordHash, user.getPasswordHash()));

					MongoUserDetails principal = new MongoUserDetails(user);
					UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
							principal, null, principal.getAuthorities());
					SecurityContextHolder.getContext().setAuthentication(authToken);

					result = new ExtDirectFormPostResult();
					result.addResultProperty(AUTH_USER,
							new UserDetailDto(principal, user));
				}
				else {
					result = new ExtDirectFormPostResult(false);
				}
				user.setPasswordResetToken(null);
				user.setPasswordResetTokenValidUntil(null);
				updates.add(Updates.unset(CUser.passwordResetToken));
				updates.add(Updates.unset(CUser.passwordResetTokenValidUntil));
				
				mongoDb.getCollection(User.class).updateOne(Filters.eq(CUser.id, user.getId()), Updates.combine(updates));
				//this.mongoDb.save(user);

				return result;
			}
		}

		return new ExtDirectFormPostResult(false);
	}

	@ExtDirectMethod
	@RequireAdminAuthority
	public UserDetailDto switchUser(String userId) {
		User switchToUser = mongoDb.getCollection(User.class).find(Filters.eq(CUser.id, userId)).first();
		//User switchToUser = this.mongoDb.findById(userId, User.class);
		if (switchToUser != null) {

			MongoUserDetails principal = new MongoUserDetails(switchToUser);
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
					principal, null, principal.getAuthorities());

			SecurityContextHolder.getContext().setAuthentication(token);

			return new UserDetailDto(principal, switchToUser);
		}

		return null;
	}

	@ExtDirectMethod(value = POLL, event = "heartbeat")
	@RequireAnyAuthority
	public void heartbeat() {
		// nothing here
	}

}
