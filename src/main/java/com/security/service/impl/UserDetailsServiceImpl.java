package com.security.service.impl;

import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 
 * @author dhekumar2
 *
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
	
	/**
	 * 
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return loadUser(username);
	}
	
	/**
	 * To load users by user name credential
	 * @param username
	 * @return
	 */
	private UserDetails loadUser(String username) {
		User user1 = new User("Dheeraj", "Dheeraj", new ArrayList<>());
		User user2 = new User("Ajay", "Ajay", new ArrayList<>());
		User userDetail = null;
		List<User> userDeatilList = new ArrayList<>();
		userDeatilList.add(user1);
		userDeatilList.add(user2);
		for(User us : userDeatilList) {
			if(us.getUsername().equals(username)) {
				userDetail = us;
				break;
			}
		}
		return userDetail;
	}

}
