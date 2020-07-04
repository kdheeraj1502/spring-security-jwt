package com.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.core.userdetails.UserDetails;

import com.security.service.impl.UserDetailsServiceImpl;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class UserDetailsServiceImplTest {
	
	@Autowired
	UserDetailsServiceImpl service;
	private final static String userName = "Dheeraj";

	@Test
	public void loadUserByUsernameTest() {
		UserDetails details = service.loadUserByUsername(userName);
		assertEquals(userName, details.getUsername());
	}
}
