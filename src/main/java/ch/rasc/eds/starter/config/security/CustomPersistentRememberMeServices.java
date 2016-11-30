package ch.rasc.eds.starter.config.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.stereotype.Component;

import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Updates;

import ch.rasc.eds.starter.Application;
import ch.rasc.eds.starter.config.AppProperties;
import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.entity.CPersistentLogin;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.PersistentLogin;
import ch.rasc.eds.starter.entity.User;

/**
 * Copy of the CustomPersistentRememberMeServices class from the
 * <a href="https://jhipster.github.io/">JHipster</a> project
 *
 * Custom implementation of Spring Security's RememberMeServices.
 * <p/>
 * Persistent tokens are used by Spring Security to automatically log in users.
 * <p/>
 * This is a specific implementation of Spring Security's remember-me authentication, but
 * it is much more powerful than the standard implementations:
 * <ul>
 * <li>It allows a user to see the list of his currently opened sessions, and invalidate
 * them</li>
 * <li>It stores more information, such as the IP address and the user agent, for audit
 * purposes
 * <li>
 * <li>When a user logs out, only his current session is invalidated, and not all of his
 * sessions</li>
 * </ul>
 * <p/>
 * This is inspired by:
 * <ul>
 * <li><a href="http://jaspan.com/improved_persistent_login_cookie_best_practice">Improved
 * Persistent Login Cookie Best Practice</a></li>
 * <li><a href="https://github.com/blog/1661-modeling-your-app-s-user-session">Github's
 * "Modeling your App's User Session"</a></li></li>
 * </ul>
 * <p/>
 * The main algorithm comes from Spring Security's PersistentTokenBasedRememberMeServices,
 * but this class couldn't be cleanly extended.
 * <p/>
 */
@Component
public class CustomPersistentRememberMeServices extends AbstractRememberMeServices {

	private static final int DEFAULT_SERIES_LENGTH = 16;

	private static final int DEFAULT_TOKEN_LENGTH = 16;

	private final SecureRandom random;

	private final MongoDb mongoDb;

	private final int tokenValidInSeconds;

	public CustomPersistentRememberMeServices(MongoDb mongoDb,
			UserDetailsService userDetailsService, AppProperties appProperties) {
		super(appProperties.getRemembermeCookieKey(), userDetailsService);

		this.tokenValidInSeconds = 60 * 60 * 24
				* appProperties.getRemembermeCookieValidInDays();

		this.mongoDb = mongoDb;
		this.random = new SecureRandom();
	}

	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens,
			HttpServletRequest request, HttpServletResponse response) {

		String series = getPersistentToken(cookieTokens);

		PersistentLogin pl = this.mongoDb.getCollection(PersistentLogin.class)
				.findOneAndUpdate(Filters.eq(CPersistentLogin.series, series),
						Updates.combine(
								Updates.set(CPersistentLogin.lastUsed, new Date()),
								Updates.set(CPersistentLogin.token, generateTokenData()),
								Updates.set(CPersistentLogin.ipAddress,
										request.getRemoteAddr()),
								Updates.set(CPersistentLogin.userAgent,
										request.getHeader(HttpHeaders.USER_AGENT))),
						new FindOneAndUpdateOptions()
								.returnDocument(ReturnDocument.AFTER));

		User user = this.mongoDb.getCollection(User.class)
				.find(Filters.and(Filters.eq(CUser.id, pl.getUserId()),
						Filters.eq(CUser.deleted, false)))
				.projection(Projections.include(CUser.loginName)).first();

		String loginName = user.getLoginName();
		String token = pl.getToken();

		Application.logger.debug(
				"Refreshing persistent login token for user '{}', series '{}'", loginName,
				series);

		addCookie(series, token, request, response);

		return getUserDetailsService().loadUserByUsername(loginName);
	}

	/**
	 * Creates a new persistent login token with a new series number, stores the data in
	 * the persistent token repository and adds the corresponding cookie to the response.
	 *
	 */
	@Override
	protected void onLoginSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication successfulAuthentication) {

		String loginName = successfulAuthentication.getName();

		Application.logger.debug("Creating new persistent login for user {}", loginName);

		User user = this.mongoDb.getCollection(User.class)
				.find(Filters.and(Filters.eq(CUser.loginName, loginName),
						Filters.eq(CUser.deleted, false)))
				.first();

		if (user != null) {
			PersistentLogin newPersistentLogin = new PersistentLogin();
			newPersistentLogin.setSeries(generateSeriesData());
			newPersistentLogin.setUserId(user.getId());
			newPersistentLogin.setToken(generateTokenData());
			newPersistentLogin.setLastUsed(new Date());
			newPersistentLogin.setIpAddress(request.getRemoteAddr());
			newPersistentLogin.setUserAgent(request.getHeader(HttpHeaders.USER_AGENT));
			this.mongoDb.getCollection(PersistentLogin.class)
					.insertOne(newPersistentLogin);

			addCookie(newPersistentLogin.getSeries(), newPersistentLogin.getToken(),
					request, response);
		}
		else {
			throw new UsernameNotFoundException(
					"User " + loginName + " was not found in the database");
		}

	}

	/**
	 * When logout occurs, only invalidate the current token, and not all user sessions.
	 * <p/>
	 * The standard Spring Security implementations are too basic: they invalidate all
	 * tokens for the current user, so when he logs out from one browser, all his other
	 * sessions are destroyed.
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {

		String rememberMeCookie = extractRememberMeCookie(request);
		if (rememberMeCookie != null && rememberMeCookie.length() != 0) {
			try {
				String[] cookieTokens = decodeCookie(rememberMeCookie);
				removePersistentLogin(getPersistentToken(cookieTokens));
			}
			catch (InvalidCookieException ice) {
				Application.logger
						.info("Invalid cookie, no persistent token could be deleted");
			}
			catch (RememberMeAuthenticationException rmae) {
				Application.logger
						.debug("No persistent token found, so no token could be deleted");
			}
		}

		super.logout(request, response, authentication);
	}

	private void removePersistentLogin(String series) {
		this.mongoDb.getCollection(PersistentLogin.class)
				.deleteOne(Filters.eq(CPersistentLogin.series, series));
	}

	/**
	 * Validate the token and return it.
	 */
	private String getPersistentToken(String[] cookieTokens) {

		if (cookieTokens.length != 2) {
			throw new InvalidCookieException("Cookie token did not contain " + 2
					+ " tokens, but contained '" + Arrays.toString(cookieTokens) + "'");
		}

		final String presentedSeries = cookieTokens[0];
		final String presentedToken = cookieTokens[1];

		PersistentLogin pl = this.mongoDb.getCollection(PersistentLogin.class)
				.find(Filters.eq(CPersistentLogin.series, presentedSeries)).first();

		if (pl == null) {
			// No series match, so we can't authenticate using this cookie
			throw new RememberMeAuthenticationException(
					"No persistent token found for series id: " + presentedSeries);
		}

		String token = pl.getToken();
		String series = pl.getSeries();

		// We have a match for this user/series combination
		if (!presentedToken.equals(token)) {
			// Presented token doesn't match stored token. Delete persistentLogin
			removePersistentLogin(series);

			throw new CookieTheftException(this.messages.getMessage(
					"PersistentTokenBasedRememberMeServices.cookieStolen",
					"Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
		}
		Instant instant = Instant.ofEpochMilli(pl.getLastUsed().getTime());
		LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());

		if (ldt.plusSeconds(this.tokenValidInSeconds).isBefore(LocalDateTime.now())) {
			removePersistentLogin(series);
			throw new RememberMeAuthenticationException("Remember-me login has expired");
		}

		return series;
	}

	private String generateSeriesData() {
		byte[] newSeries = new byte[DEFAULT_SERIES_LENGTH];
		this.random.nextBytes(newSeries);
		return Base64.getEncoder().encodeToString(newSeries);
	}

	private String generateTokenData() {
		byte[] newToken = new byte[DEFAULT_TOKEN_LENGTH];
		this.random.nextBytes(newToken);
		return Base64.getEncoder().encodeToString(newToken);
	}

	private void addCookie(String series, String token, HttpServletRequest request,
			HttpServletResponse response) {
		setCookie(new String[] { series, token }, this.tokenValidInSeconds, request,
				response);
	}

}
