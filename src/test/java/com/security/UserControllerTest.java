package com.security;

import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.security.model.ApplicationUser;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class UserControllerTest {

	@Autowired
	private AuthenticationManager manager;
	
	private ApplicationUser auth;
	
	@BeforeEach
	public void setUp() {
		auth = new ApplicationUser();
		auth.setUsername("Dheeraj");
		auth.setPassword("Dheeraj");
	}

	@Test
	public void createAuthenticationTokenTest() {
		Authentication authentication = manager
				.authenticate(new UsernamePasswordAuthenticationToken(auth.getUsername(), auth.getPassword()));
		assertTrue(authentication.isAuthenticated());
	}
}