package jca.crypto.asymmetric.impl;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jca.crypto.KeyPairType;
import jca.crypto.asymmetric.api.IKeyPairGenerator;



@Component
public class EcKeyGenerator implements IKeyPairGenerator{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EcKeyGenerator.class);

	@Override
	public KeyPair generateKeyPair() {
		EllipticCurve ellipticCurve = new EllipticCurve(
				new ECFieldFp(
						new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
				new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
				new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
		ECPoint ecPoint = new ECPoint(
				new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
				new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
		ECParameterSpec ecParameterSpec = new ECParameterSpec(
				ellipticCurve,
				ecPoint,
				new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
				1);

		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC","BC");
			keyPairGenerator.initialize(ecParameterSpec);
			keyPair = keyPairGenerator.generateKeyPair();
			//publicKey will be of type  org.bouncycastle.jcajce.provider.asymmetric.rsa.BCECPublicKey
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			//privateKey will be of type org.bouncycastle.jcajce.provider.asymmetric.rsa.BCECPrivateCrtKey
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			LOGGER.info("EC Private key and Public key generated");
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.EC;
	}

}
