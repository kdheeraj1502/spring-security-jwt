package com.security.model;

import java.util.Map;

import org.springframework.stereotype.Component;

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
@Component
public class ApplicationResponse {

	private Map<String, String> apiResponse;
}
