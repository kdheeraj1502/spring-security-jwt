package com.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 
 * @author dhekumar2
 *
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApplicationUser {
	private String username;
	private String password;

}
