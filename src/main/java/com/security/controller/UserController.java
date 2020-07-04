package com.security.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.security.config.AESEncryptionConfig;
import com.security.model.ApplicationResponse;
import com.security.model.ApplicationUser;
import com.security.model.AuthenticationResponse;
import com.security.service.impl.UserDetailsServiceImpl;
import com.security.util.JWTAuthenticationUtil;

/**
 * 
 * @author dhekumar2
 *
 */
@RestController
public class UserController {

	private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

	@Autowired
	AuthenticationManager manager;

	@Autowired
	JWTAuthenticationUtil authenticationUtil;

	String jwt;

	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Value("${secret.key}")
	private String SECRET_KEY;

	@Autowired
	private ApplicationResponse respnse;

	private Map<String, String> response;

	UserController() {
		response = new HashMap<>();
	}

	/**
	 * Fetch details
	 * 
	 * @param httpServletResponse
	 * @return
	 * @throws IOException
	 */
	@GetMapping("/details")
	public ResponseEntity<Map<String, String>> getUserDeatil() throws IOException {
		try {
			if(!authenticationUtil.isTokenExpire(jwt)) {
				return new ResponseEntity<>(successLoginResponse(), HttpStatus.OK);
			}
		} catch (Exception ex) {
			return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
		}
		return new ResponseEntity<>(tokenExpiredResponse(), HttpStatus.BAD_REQUEST);
	}

	/**
	 * To generate jwt after authenticated log in
	 * 
	 * @param auth
	 * @return
	 * @throws Exception
	 */
	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody ApplicationUser auth) throws Exception {
		try {
			manager.authenticate(new UsernamePasswordAuthenticationToken(auth.getUsername(), auth.getPassword()));
		} catch (BadCredentialsException ex) {
			throw new Exception("Incorrect username and password");
		}
		final UserDetails userDetails = userDetailsService.loadUserByUsername(auth.getUsername());
		jwt = authenticationUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(AESEncryptionConfig.encrypt(jwt, SECRET_KEY)));
	}

	/**
	 * Helper method to generate api response
	 * 
	 * @return
	 */
	private Map<String, String> successLoginResponse() {
		response.put("authentication", "successfully logined in");
		response.put(jwt, "jwt - token");
		respnse.setApiResponse(response);
		return response;
	}

	/**
	 * Helper method to generate api response
	 * 
	 * @return
	 */
	private Map<String, String> tokenExpiredResponse() {
		response.put("authentication", "Token Expired");
		respnse.setApiResponse(response);
		return response;
	}

}
