package jca.crypto.asymmetric.certificates;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import jca.crypto.asymmetric.api.IKeyPairGenerator;

@Component
public class CertificateService {

	@Qualifier("RsaKeyGenerator")
	@Autowired
	private IKeyPairGenerator rsaPairGenerator;

	public void createCertificate() {
		KeyPair rsaKeyPair = rsaPairGenerator.generateKeyPair();
	}

	public static X509Certificate makeV3Certificate(X509Certificate caCertificate, PrivateKey caPrivateKey,
			PublicKey eePublicKey) throws GeneralSecurityException, CertIOException, OperatorCreationException {
		LocalDateTime validFrom = LocalDateTime.of(2021, 12, 31, 0, 0);
		LocalDateTime expiry = LocalDateTime.of(2023, 12, 31, 0, 0);

		X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(caCertificate.getSubjectX500Principal(), // issuer
				BigInteger.valueOf(System.nanoTime()).multiply(BigInteger.valueOf(10)),
				Date.from(validFrom.toInstant(ZoneOffset.UTC)), // start time
				Date.from(expiry.toInstant(ZoneOffset.UTC)), // expiry time
				new X500Principal("CN=SFSF"), // subject
				eePublicKey); // subject public key
		
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		v3CertBldr.addExtension(new ASN1ObjectIdentifier("subjectKeyIdentifier"), false,
				extUtils.createSubjectKeyIdentifier(eePublicKey));

		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");
		return new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
	}

}
