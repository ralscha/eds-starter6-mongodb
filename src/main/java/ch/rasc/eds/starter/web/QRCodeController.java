package ch.rasc.eds.starter.web;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import ch.rasc.eds.starter.config.MongoDb;
import ch.rasc.eds.starter.config.security.MongoUserDetails;
import ch.rasc.eds.starter.config.security.RequireAnyAuthority;
import ch.rasc.eds.starter.entity.User;

@Controller
public class QRCodeController {

	private final MongoDb mongoDb;

	private final String appName;

	@Autowired
	QRCodeController(MongoDb mongoDb, @Value("${info.app.name}") String appName) {
		this.mongoDb = mongoDb;
		this.appName = appName;
	}

	@RequireAnyAuthority
	@RequestMapping(value = "/qr", method = RequestMethod.GET)
	public void qrcode(HttpServletResponse response,
			@AuthenticationPrincipal MongoUserDetails userDetails)
					throws WriterException, IOException {

		User user = userDetails.getUser(this.mongoDb);
		if (user != null && StringUtils.hasText(user.getSecret())) {
			response.setContentType("image/png");
			String contents = "otpauth://totp/" + user.getEmail() + "?secret="
					+ user.getSecret() + "&issuer=" + this.appName;

			QRCodeWriter writer = new QRCodeWriter();
			BitMatrix matrix = writer.encode(contents, BarcodeFormat.QR_CODE, 200, 200);
			MatrixToImageWriter.writeToStream(matrix, "PNG", response.getOutputStream());
			response.getOutputStream().flush();
		}
	}

}
