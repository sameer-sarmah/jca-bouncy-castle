package jca.crypto.asymmetric.signature;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.springframework.stereotype.Component;

@Component
public class SignatureService {
	
	public byte[] generateSignature(PrivateKey dsaPrivate, byte[] input) throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA", "BC");
		signature.initSign(dsaPrivate);
		signature.update(input);
		return signature.sign();
	}

	public boolean verifySignature(PublicKey dsaPublic, byte[] input, byte[] encSignature)
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withRSA", "BC");
		signature.initVerify(dsaPublic);
		signature.update(input);
		return signature.verify(encSignature);
	}

}
