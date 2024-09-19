import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JweDecryptUtil {

	@Value("${security.private-file}")
	private String KEYSTORE_FILE;
	@Value("${server.ssl.key-store-alias}")
	private String ALIAS;
	@Value("${server.ssl.key-store-password}")
	private String KEYSTORE_PASSWORD;

	public String decrypt(String jweString) throws ParseException, JOSEException {
		log.info("JweDecryptUtil Decrypt Started {}", KEYSTORE_FILE);
		PrivateKey privateKey = null;
		try {
			var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(new ClassPathResource(this.KEYSTORE_FILE).getInputStream(),
					this.KEYSTORE_PASSWORD.toCharArray());

			privateKey = (PrivateKey) keyStore.getKey(this.ALIAS, this.KEYSTORE_PASSWORD.toCharArray());


		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		}
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload(jweString);
		JWEObject jweObject = new JWEObject(header, payload);
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		jweObject = JWEObject.parse(jweString);
		jweObject.decrypt(decrypter);
		payload = jweObject.getPayload();
		return payload.toString();
	}

}
