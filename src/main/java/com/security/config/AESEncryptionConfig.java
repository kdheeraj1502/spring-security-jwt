package com.security.config;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES encryption
 * @author dhekumar2
 *
 */
public class AESEncryptionConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(AESEncryptionConfig.class);

	private static SecretKeySpec secretKey;
	private static byte[] key;

	/**
	 * Set key
	 * @param myKey
	 */
	public static void setKey(String myKey) {
		MessageDigest sha = null;
		try {
			key = myKey.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException e) {
			LOGGER.info("Algorithm not found");
		} catch (UnsupportedEncodingException e) {
			LOGGER.info("Encoding not supported");
		}
	}
	
	/**
	 * Enryption method
	 * @param strToEncrypt
	 * @param secret
	 * @return
	 */
	public static String encrypt(String strToEncrypt, String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		} catch (Exception e) {
			 LOGGER.info("AES Encryption failed");
		}
		return null;
	}

	/**
	 * Decryption method
	 * @param strToDecrypt
	 * @param secret
	 * @return
	 */
	public static String decrypt(String strToDecrypt, String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception e) {
			LOGGER.info("AES Decryption failed");
		}
		return null;
	}
}