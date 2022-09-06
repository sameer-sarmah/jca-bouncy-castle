package jca.crypto.digest.api;

import javax.crypto.SecretKey;

public interface IHashGenerator {
	public SecretKey generateSecretKey() ;
}
