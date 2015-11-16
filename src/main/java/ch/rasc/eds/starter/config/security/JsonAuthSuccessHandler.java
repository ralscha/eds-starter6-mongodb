package ch.rasc.eds.starter.config.security;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Updates;

import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.dto.UserDetailDto;
import ch.rasc.eds.starter.entity.CUser;
import ch.rasc.eds.starter.entity.User;
import ch.rasc.eds.starter.service.SecurityService;

@Component
public class JsonAuthSuccessHandler implements AuthenticationSuccessHandler {

	private final MongoDb mongoDb;

	private final ObjectMapper objectMapper;

	@Autowired
	public JsonAuthSuccessHandler(MongoDb mongoDb, ObjectMapper objectMapper) {
		this.mongoDb = mongoDb;
		this.objectMapper = objectMapper;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
					throws IOException, ServletException {

		Map<String, Object> result = new HashMap<>();
		result.put("success", true);

		MongoUserDetails userDetails = (MongoUserDetails) authentication.getPrincipal();
		if (userDetails != null) {
			User user;
			if (!userDetails.isPreAuth()) {

				user = mongoDb.getCollection(User.class).findOneAndUpdate(
						Filters.eq(CUser.id, userDetails.getUserDbId()),
						Updates.set(CUser.lastAccess, new Date()),
						new FindOneAndUpdateOptions()
								.returnDocument(ReturnDocument.AFTER));

				// user = this.mongoDb.findAndModify(
				// Query.query(
				// Criteria.where(CUser.id).is(userDetails.getUserDbId())),
				// Update.update(CUser.lastAccess, new Date()), User.class);
			}
			else {
				user = mongoDb.getCollection(User.class)
						.find(Filters.eq(CUser.id, userDetails.getUserDbId())).first();
				// user = this.mongoDb.findById(userDetails.getUserDbId(), User.class);
			}
			result.put(SecurityService.AUTH_USER, new UserDetailDto(userDetails, user));
		}

		CsrfCookieFilter.addCsrfCookie(request, response);

		response.getWriter().print(this.objectMapper.writeValueAsString(result));
		response.getWriter().flush();
	}

}