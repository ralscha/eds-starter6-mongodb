package ch.rasc.eds.starter.config.security;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import ch.rasc.eds.starter.dto.UserDetailDto;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.service.SecurityService;

@Component
public class JsonAuthSuccessHandler implements AuthenticationSuccessHandler {

	private final MongoTemplate mongoTemplate;

	private final ObjectMapper objectMapper;

	@Autowired
	public JsonAuthSuccessHandler(MongoTemplate mongoTemplate,
			ObjectMapper objectMapper) {
		this.mongoTemplate = mongoTemplate;
		this.objectMapper = objectMapper;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
					throws IOException, ServletException {

		Map<String, Object> result = new HashMap<>();
		result.put("success", true);

		MongoUserDetails jpaUserDetails = (MongoUserDetails) authentication
				.getPrincipal();
		if (jpaUserDetails != null) {
			User user;
			if (!jpaUserDetails.isPreAuth()) {
				user = this.mongoTemplate.findAndModify(
						Query.query(Criteria.where(CUser.id)
								.is(jpaUserDetails.getUserDbId())),
						Update.update(CUser.lastAccess, new Date()), User.class);
			}
			else {
				user = this.mongoTemplate.findById(jpaUserDetails.getUserDbId(),
						User.class);
			}
			result.put(SecurityService.AUTH_USER,
					new UserDetailDto(jpaUserDetails, user));
		}

		CsrfCookieFilter.addCsrfCookie(request, response);

		response.getWriter().print(this.objectMapper.writeValueAsString(result));
		response.getWriter().flush();
	}

}