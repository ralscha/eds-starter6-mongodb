package ch.rasc.eds.starter.config.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.mongodb.morphia.Datastore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;

public class MongoUserDetails implements UserDetails {

	private static final long serialVersionUID = 1L;

	private Collection<GrantedAuthority> authorities;

	private final Collection<GrantedAuthority> userAuthorities;

	private final String password;

	private final String email;

	private final boolean enabled;

	private final String userDbId;

	private final boolean locked;

	private final Locale locale;

	private boolean screenLocked;

	public MongoUserDetails(User user) {
		this.userDbId = user.getId();

		this.password = user.getPasswordHash();
		this.email = user.getEmail();
		this.enabled = user.isEnabled();

		if (StringUtils.hasText(user.getLocale())) {
			this.locale = new Locale(user.getLocale());
		}
		else {
			this.locale = Locale.ENGLISH;
		}

		this.locked = user.getLockedOutUntil() != null
				&& user.getLockedOutUntil().after(new Date());

		if (user.getAuthorities() != null) {
			this.userAuthorities = createAuthorityList(user.getAuthorities());
		}
		else {
			this.userAuthorities = Collections.emptyList();
		}

		if (StringUtils.hasText(user.getSecret())) {
			this.authorities = Collections.unmodifiableCollection(
					AuthorityUtils.createAuthorityList("PRE_AUTH"));
		}
		else {
			this.authorities = Collections.unmodifiableCollection(this.userAuthorities);
		}
	}

	public boolean isPreAuth() {
		return hasAuthority("PRE_AUTH");
	}

	public void grantAuthorities() {
		this.authorities = Collections.unmodifiableCollection(this.userAuthorities);
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getPassword() {
		return this.password;
	}

	@Override
	public String getUsername() {
		return this.email;
	}

	public User getUser(Datastore ds) {
		User user = ds.createQuery(User.class).field(CUser.id).equal(getUserDbId())
				.field(CUser.deleted).equal(false).get();
		if (user != null) {
			user.setTwoFactorAuth(StringUtils.hasText(user.getSecret()));
			return user;
		}
		return null;
	}

	public String getUserDbId() {
		return this.userDbId;
	}

	public Locale getLocale() {
		return this.locale;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return !this.locked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return this.enabled;
	}

	public boolean hasAuthority(String authority) {
		return getAuthorities().stream()
				.anyMatch(a -> authority.equals(a.getAuthority()));
	}

	public boolean isScreenLocked() {
		return this.screenLocked;
	}

	public void setScreenLocked(boolean screenLocked) {
		this.screenLocked = screenLocked;
	}

	private static List<GrantedAuthority> createAuthorityList(
			Collection<String> stringAuthorities) {
		List<GrantedAuthority> authorities = new ArrayList<>(stringAuthorities.size());

		for (String stringAuthority : stringAuthorities) {
			authorities.add(new SimpleGrantedAuthority(stringAuthority));
		}

		return authorities;
	}

}
