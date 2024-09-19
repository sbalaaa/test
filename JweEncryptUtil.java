import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JweEncryptUtil {

	@Value("${security.public-file}")
	private String KEYSTORE_FILE;
	@Value("${server.ssl.key-store-alias}")
	private String ALIAS;
	@Value("${server.ssl.key-store-password}")
	private String KEYSTORE_PASSWORD;

	public String encrypt(String input) throws JOSEException {

		log.info("JweEncryptUtil Started {}", KEYSTORE_FILE);
		RSAPublicKey publicKey = null;
		try {
			var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(new ClassPathResource(this.KEYSTORE_FILE).getInputStream(),
					this.KEYSTORE_PASSWORD.toCharArray());
			Certificate certificate = keyStore.getCertificate(this.ALIAS);
			publicKey = (RSAPublicKey)certificate.getPublicKey();

		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
			throw new RuntimeException(e);
		}
		
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload(input);
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		JWEObject jweObject = new JWEObject(header, payload);
		jweObject.encrypt(encrypter);
		String jweString = jweObject.serialize();
		return jweString;
	}


}
