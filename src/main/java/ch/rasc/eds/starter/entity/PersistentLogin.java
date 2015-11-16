package ch.rasc.eds.starter.entity;

import java.util.Date;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import ch.rasc.bsoncodec.annotation.BsonDocument;
import ch.rasc.bsoncodec.annotation.Id;
import ch.rasc.bsoncodec.annotation.Transient;
import ch.rasc.extclassgenerator.Model;
import ch.rasc.extclassgenerator.ModelField;

@BsonDocument
@Model(value = "Starter.model.PersistentLogin", idProperty = "series",
		readMethod = "userConfigService.readPersistentLogins", writeAllFields = false,
		destroyMethod = "userConfigService.destroyPersistentLogin")
@JsonInclude(Include.NON_NULL)
public class PersistentLogin {

	@Id
	private String series;

	//todo @Indexed
	private String userId;

	@JsonIgnore
	@NotNull
	private String token;

	@ModelField(dateFormat = "time")
	private Date lastUsed;

	@Size(min = 0, max = 39)
	private String ipAddress;

	@JsonIgnore
	private String userAgent;

	@Transient
	private String userAgentName;

	@Transient
	private String userAgentVersion;

	@Transient
	private String operatingSystem;

	public String getSeries() {
		return this.series;
	}

	public void setSeries(String series) {
		this.series = series;
	}

	public String getToken() {
		return this.token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public Date getLastUsed() {
		return this.lastUsed;
	}

	public void setLastUsed(Date lastUsed) {
		this.lastUsed = lastUsed;
	}

	public String getIpAddress() {
		return this.ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getUserAgent() {
		return this.userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public String getUserId() {
		return this.userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserAgentName() {
		return this.userAgentName;
	}

	public void setUserAgentName(String userAgentName) {
		this.userAgentName = userAgentName;
	}

	public String getUserAgentVersion() {
		return this.userAgentVersion;
	}

	public void setUserAgentVersion(String userAgentVersion) {
		this.userAgentVersion = userAgentVersion;
	}

	public String getOperatingSystem() {
		return this.operatingSystem;
	}

	public void setOperatingSystem(String operatingSystem) {
		this.operatingSystem = operatingSystem;
	}

}