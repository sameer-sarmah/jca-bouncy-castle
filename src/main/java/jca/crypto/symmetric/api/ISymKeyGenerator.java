package jca.crypto.symmetric.api;

import javax.crypto.SecretKey;

import jca.crypto.KeyType;

public interface ISymKeyGenerator {
	SecretKey generateSecretKey() ;
	KeyType getType();
}
