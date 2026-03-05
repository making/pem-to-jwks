package am.ik.pemtojwks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class JwksGenerator implements CommandLineRunner {

	private final JwtProps jwtProps;

	private final ObjectMapper objectMapper;

	private final Logger logger = LoggerFactory.getLogger(JwksGenerator.class);

	public JwksGenerator(JwtProps jwtProps, ObjectMapper objectMapper) {
		this.jwtProps = jwtProps;
		this.objectMapper = objectMapper;
	}

	// https://github.com/kubernetes/kubernetes/pull/78502
	static String keyIDFromPublicKey(PublicKey publicKey) throws Exception {
		byte[] publicKeyDERBytes = publicKey.getEncoded();
		MessageDigest hasher = MessageDigest.getInstance("SHA-256");
		byte[] publicKeyDERHash = hasher.digest(publicKeyDERBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyDERHash);
	}

	@Override
	public void run(String... args) throws Exception {
		String keyId = keyIDFromPublicKey(this.jwtProps.publicKey());
		var key = new RSAKey.Builder(this.jwtProps.publicKey()).keyID(keyId).build();
		Map<String, Object> jwks = new JWKSet(key).toJSONObject();
		logger.info("Writing JWKS to  {}", this.jwtProps.jwksOutput().getFile().getAbsoluteFile());
		try (OutputStream outputStream = this.jwtProps.jwksOutput().getOutputStream()) {
			outputStream.write(this.objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(jwks));
		}
	}

}
