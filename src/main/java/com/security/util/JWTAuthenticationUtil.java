package com.security.util;

import java.util.function.Function;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import com.security.config.AESEncryptionConfig;
import com.security.service.impl.UserDetailsServiceImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 
 * @author dhekumar2
 *
 */
@Component
@EnableScheduling
@PropertySource("classpath:application.properties")
public class JWTAuthenticationUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthenticationUtil.class);

	@Value("${secret.key}")
	private String SECRET_KEY;

	@Autowired
	private Environment environment;

	UserDetails details;

	/**
	 * 
	 * @param token
	 * @return
	 */
	public String extractUserName(String token) {
		return extractClaims(token, Claims::getSubject);
	}

	/**
	 * 
	 * @param token
	 * @return
	 */
	public Date extractExpirationTime(String token) {
		return extractClaims(token, Claims::getExpiration);
	}

	/**
	 * 
	 * @param token
	 * @return
	 */
	public boolean isTokenExpire(String token) {
		try {
			return extractExpirationTime(token).before(new Date());
		} catch (Exception ex) {
			return true;
		}
	}

	/**
	 * 
	 * @param <T>
	 * @param token
	 * @param claimResolver
	 * @return
	 */
	public <T> T extractClaims(String token, Function<Claims, T> claimResolver) {
		Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	/**
	 * 
	 * @param token
	 * @return
	 */
	private Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}

	/**
	 * 
	 * @param userDetails
	 * @return
	 */
	public String generateToken(UserDetails userDetails) {
		details = userDetails;
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userDetails.getUsername());
	}

	/**
	 * 
	 * @param claims
	 * @param subject
	 * @return
	 */
	public String createToken(Map<String, Object> claims, String subject) {
		final String EXPIRY_TIME = environment.getProperty("jwt.expiry.time");
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + Integer.valueOf(EXPIRY_TIME)))
				.signWith(SignatureAlgorithm.HS384, SECRET_KEY).compact();

	}

	/**
	 * 
	 * @param token
	 * @param userDetails
	 * @return
	 */
	public boolean validateJWT(String token, UserDetails userDetails) {
		final String username = extractUserName(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpire(token));
	}

	/*	*//**
			 * to refresh jwt after every 4 minute and 50 seconds
			 *//*
				 * @Scheduled(fixedDelayString = "${jwt.refresh.time}") public void run() {
				 * while (details != null) { generateToken(details); } }
				 */

}
