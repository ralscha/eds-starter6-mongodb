package ch.rasc.eds.starter.service;

import static ch.ralscha.extdirectspring.annotation.ExtDirectMethodType.POLL;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.mongodb.morphia.Datastore;
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

	private final Datastore ds;

	private final PasswordEncoder passwordEncoder;

	private final MailService mailService;

	private final ApplicationEventPublisher applicationEventPublisher;

	@Autowired
	public SecurityService(Datastore ds, PasswordEncoder passwordEncoder,
			MailService mailService,
			ApplicationEventPublisher applicationEventPublisher) {
		this.ds = ds;
		this.passwordEncoder = passwordEncoder;
		this.mailService = mailService;
		this.applicationEventPublisher = applicationEventPublisher;
	}

	@ExtDirectMethod
	public UserDetailDto getAuthUser(
			@AuthenticationPrincipal MongoUserDetails jpaUserDetails) {

		if (jpaUserDetails != null) {
			User user = jpaUserDetails.getUser(this.ds);
			UserDetailDto userDetailDto = new UserDetailDto(jpaUserDetails, user);

			if (!jpaUserDetails.isPreAuth()) {
				this.ds.updateFirst(
						this.ds.createQuery(User.class).field(CUser.id)
								.equal(jpaUserDetails.getUserDbId()),
						this.ds.createUpdateOperations(User.class).set(CUser.lastAccess,
								new Date()));
			}

			return userDetailDto;
		}

		return null;
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	@PreAuthorize("hasAuthority('PRE_AUTH')")
	public ExtDirectFormPostResult signin2fa(HttpServletRequest request,
			@AuthenticationPrincipal MongoUserDetails jpaUserDetails,
			@RequestParam("code") int code) {

		User user = jpaUserDetails.getUser(this.ds);
		if (user != null) {
			if (TotpAuthUtil.verifyCode(user.getSecret(), code, 3)) {

				this.ds.updateFirst(
						this.ds.createQuery(User.class).field(CUser.id)
								.equal(jpaUserDetails.getUserDbId()),
						this.ds.createUpdateOperations(User.class).set(CUser.lastAccess,
								new Date()));

				jpaUserDetails.grantAuthorities();

				Authentication newAuth = new UsernamePasswordAuthenticationToken(
						jpaUserDetails, null, jpaUserDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(newAuth);

				ExtDirectFormPostResult result = new ExtDirectFormPostResult();
				result.addResultProperty(AUTH_USER,
						new UserDetailDto(jpaUserDetails, user));
				return result;
			}

			BadCredentialsException excp = new BadCredentialsException(
					"Bad verification code");
			AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
					SecurityContextHolder.getContext().getAuthentication(), excp);
			this.applicationEventPublisher.publishEvent(event);

			user = jpaUserDetails.getUser(this.ds);
			if (user.getLockedOutUntil() != null) {
				HttpSession session = request.getSession(false);
				if (session != null) {
					Application.logger
							.debug("Invalidating session: " + session.getId());
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
			@AuthenticationPrincipal MongoUserDetails jpaUserDetails) {
		jpaUserDetails.setScreenLocked(true);
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	@RequireAnyAuthority
	public ExtDirectFormPostResult disableScreenLock(
			@AuthenticationPrincipal MongoUserDetails jpaUserDetails,
			@RequestParam("password") String password) {

		// todo test
		User user = this.ds.createQuery(User.class).field(CUser.id)
				.equal(jpaUserDetails.getUserDbId())
				.retrievedFields(true, CUser.passwordHash).get();
		boolean matches = this.passwordEncoder.matches(password, user.getPasswordHash());
		jpaUserDetails.setScreenLocked(!matches);
		ExtDirectFormPostResult result = new ExtDirectFormPostResult(matches);

		return result;
	}

	@ExtDirectMethod(ExtDirectMethodType.FORM_POST)
	public ExtDirectFormPostResult resetRequest(@RequestParam("email") String email) {

		String token = UUID.randomUUID().toString();
		User user = this.ds.findAndModify(
				this.ds.createQuery(User.class).field(CUser.email).equal(email)
						.field(CUser.deleted).equal(false),
				this.ds.createUpdateOperations(User.class)
						.set(CUser.passwordResetTokenValidUntil,
								Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusHours(4)
										.toInstant()))
						.set(CUser.passwordResetToken, token));

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
			User user = this.ds.createQuery(User.class).field(CUser.passwordResetToken)
					.equal(decodedToken).field(CUser.deleted).equal(false)
					.field(CUser.enabled).equal(true).get();

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
				this.ds.save(user);

				return result;
			}
		}

		return new ExtDirectFormPostResult(false);
	}

	@ExtDirectMethod
	@RequireAdminAuthority
	public UserDetailDto switchUser(String userId) {
		User switchToUser = this.ds.get(User.class, userId);
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
