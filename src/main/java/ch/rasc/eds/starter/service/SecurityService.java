package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.POLL;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
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

import ch.ralscha.extdirectspring.annotation.ExtDirectMethod;
import ch.ralscha.extdirectspring.annotation.ExtDirectMethodType;
import ch.ralscha.extdirectspring.bean.ExtDirectFormPostResult;
import ch.rasc.eds.starter.Application;
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

	private final MongoTemplate mongoTemplate;

	private final PasswordEncoder passwordEncoder;

	private final MailService mailService;

	private final ApplicationEventPublisher applicationEventPublisher;

	@Autowired
	public SecurityService(MongoTemplate mongoTemplate, PasswordEncoder passwordEncoder,
			MailService mailService,
			ApplicationEventPublisher applicationEventPublisher) {
		this.mongoTemplate = mongoTemplate;
		this.passwordEncoder = passwordEncoder;
		this.mailService = mailService;
		this.applicationEventPublisher = applicationEventPublisher;
	}

	@ExtDirectMethod
	public UserDetailDto getAuthUser(
			@AuthenticationPrincipal MongoUserDetails userDetails) {

		if (userDetails != null) {
			User user = userDetails.getUser(this.mongoTemplate);
			UserDetailDto userDetailDto = new UserDetailDto(userDetails, user);

			if (!userDetails.isPreAuth()) {
				this.mongoTemplate.updateFirst(
						Query.query(Criteria.where(CUser.id)
								.is(userDetails.getUserDbId())),
						Update.update(CUser.lastAccess, new Date()), User.class);
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

		User user = userDetails.getUser(this.mongoTemplate);
		if (user != null) {
			if (TotpAuthUtil.verifyCode(user.getSecret(), code, 3)) {

				this.mongoTemplate.updateFirst(
						Query.query(Criteria.where(CUser.id)
								.is(userDetails.getUserDbId())),
						Update.update(CUser.lastAccess, new Date()), User.class);

				userDetails.grantAuthorities();

				Authentication newAuth = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(newAuth);

				ExtDirectFormPostResult result = new ExtDirectFormPostResult();
				result.addResultProperty(AUTH_USER,
						new UserDetailDto(userDetails, user));
				return result;
			}

			BadCredentialsException excp = new BadCredentialsException(
					"Bad verification code");
			AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
					SecurityContextHolder.getContext().getAuthentication(), excp);
			this.applicationEventPublisher.publishEvent(event);

			user = userDetails.getUser(this.mongoTemplate);
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
	public void enableScreenLock(
			@AuthenticationPrincipal MongoUserDetails userDetails) {
		userDetails.setScreenLocked(true);
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	@RequireAnyAuthority
	public ExtDirectFormPostResult disableScreenLock(
			@AuthenticationPrincipal MongoUserDetails userDetails,
			@RequestParam("password") String password) {

		Query query = Query
				.query(Criteria.where(CUser.id).is(userDetails.getUserDbId()));
		query.fields().include(CUser.passwordHash);
		User user = this.mongoTemplate.findOne(query, User.class);
		boolean matches = this.passwordEncoder.matches(password, user.getPasswordHash());
		userDetails.setScreenLocked(!matches);
		ExtDirectFormPostResult result = new ExtDirectFormPostResult(matches);

		return result;
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	public ExtDirectFormPostResult resetRequest(@RequestParam("email") String email) {

		String token = UUID.randomUUID().toString();
		User user = this.mongoTemplate.findAndModify(
				Query.query(Criteria.where(CUser.email).is(email).and(CUser.deleted)
						.is(false)),
				Update.update(CUser.passwordResetTokenValidUntil,
						Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusHours(4)
								.toInstant()))
						.set(CUser.passwordResetToken, token),
				FindAndModifyOptions.options().returnNew(true).upsert(false), User.class);

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
			User user = this.mongoTemplate.findOne(
					Query.query(Criteria.where(CUser.passwordResetToken).is(decodedToken)
							.and(CUser.deleted).is(false).and(CUser.enabled).is(true)),
					User.class);

			if (user != null && user.getPasswordResetTokenValidUntil() != null) {

				ExtDirectFormPostResult result;

				if (user.getPasswordResetTokenValidUntil().after(new Date())) {
					user.setPasswordHash(this.passwordEncoder.encode(newPassword));
					user.setSecret(null);

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
				this.mongoTemplate.save(user);

				return result;
			}
		}

		return new ExtDirectFormPostResult(false);
	}

	@ExtDirectMethod
	@RequireAdminAuthority
	public UserDetailDto switchUser(String userId) {
		User switchToUser = this.mongoTemplate.findById(userId, User.class);
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
