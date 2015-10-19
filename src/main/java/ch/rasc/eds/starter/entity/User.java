package ch.rasc.eds.starter.entity;

import java.util.Date;
import java.util.List;

import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotBlank;
import org.mongodb.morphia.annotations.Entity;
import org.mongodb.morphia.annotations.Id;
import org.mongodb.morphia.annotations.IndexOptions;
import org.mongodb.morphia.annotations.Indexed;
import org.mongodb.morphia.annotations.Transient;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import ch.rasc.extclassgenerator.Model;
import ch.rasc.extclassgenerator.ModelField;

@Entity(noClassnameStored = true)
@Model(value = "Starter.model.User", readMethod = "userService.read",
		createMethod = "userService.update", updateMethod = "userService.update",
		destroyMethod = "userService.destroy", paging = true, identifier = "uuid")
@JsonInclude(Include.NON_NULL)
public class User {

	@ModelField(useNull = true, convert = "null")
	@Id
	private String id;

	@NotBlank(message = "{fieldrequired}")
	private String lastName;

	@NotBlank(message = "{fieldrequired}")
	private String firstName;

	@Email(message = "{invalidemail}")
	@Indexed(options = @IndexOptions(unique = true) )
	private String email;

	private List<String> authorities;

	@JsonIgnore
	private String passwordHash;

	@NotBlank(message = "{fieldrequired}")
	private String locale;

	private boolean enabled;

	@ModelField(persist = false)
	private int failedLogins;

	@ModelField(dateFormat = "time", persist = false)
	private Date lockedOutUntil;

	@ModelField(dateFormat = "time", persist = false)
	private Date lastAccess;

	@JsonIgnore
	private String passwordResetToken;

	@JsonIgnore
	private Date passwordResetTokenValidUntil;

	@JsonIgnore
	private boolean deleted;

	@JsonIgnore
	private String secret;

	@ModelField(persist = false)
	@Transient
	private boolean twoFactorAuth;

	public String getId() {
		return this.id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getLastName() {
		return this.lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getFirstName() {
		return this.firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getEmail() {
		return this.email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public List<String> getAuthorities() {
		return this.authorities;
	}

	public void setAuthorities(List<String> authorities) {
		this.authorities = authorities;
	}

	public String getPasswordHash() {
		return this.passwordHash;
	}

	public void setPasswordHash(String passwordHash) {
		this.passwordHash = passwordHash;
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getLocale() {
		return this.locale;
	}

	public void setLocale(String locale) {
		this.locale = locale;
	}

	public int getFailedLogins() {
		return this.failedLogins;
	}

	public void setFailedLogins(int failedLogins) {
		this.failedLogins = failedLogins;
	}

	public Date getLockedOutUntil() {
		return this.lockedOutUntil;
	}

	public void setLockedOutUntil(Date lockedOutUntil) {
		this.lockedOutUntil = lockedOutUntil;
	}

	public Date getLastAccess() {
		return this.lastAccess;
	}

	public void setLastAccess(Date lastAccess) {
		this.lastAccess = lastAccess;
	}

	public String getPasswordResetToken() {
		return this.passwordResetToken;
	}

	public void setPasswordResetToken(String passwordResetToken) {
		this.passwordResetToken = passwordResetToken;
	}

	public Date getPasswordResetTokenValidUntil() {
		return this.passwordResetTokenValidUntil;
	}

	public void setPasswordResetTokenValidUntil(Date passwordResetTokenValidUntil) {
		this.passwordResetTokenValidUntil = passwordResetTokenValidUntil;
	}

	public boolean isDeleted() {
		return this.deleted;
	}

	public void setDeleted(boolean deleted) {
		this.deleted = deleted;
	}

	public String getSecret() {
		return this.secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public boolean isTwoFactorAuth() {
		return this.twoFactorAuth;
	}

	public void setTwoFactorAuth(boolean twoFactorAuth) {
		this.twoFactorAuth = twoFactorAuth;
	}

}
