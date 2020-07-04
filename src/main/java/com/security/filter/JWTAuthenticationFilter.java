package com.security.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.config.AESEncryptionConfig;
import com.security.controller.UserController;
import com.security.service.impl.UserDetailsServiceImpl;
import com.security.util.JWTAuthenticationUtil;
import io.jsonwebtoken.ExpiredJwtException;

/**
 * 
 * @author dhekumar2
 *
 */
@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	UserDetailsServiceImpl userDeatislService;

	@Autowired
	JWTAuthenticationUtil authenticationUtil;
	
	private ObjectMapper mapper;

	@Value("${secret.key}")
	private String SECRET_KEY;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws ServletException, IOException {
		final String authorizationHeader = request.getHeader("Authorization");
		if(!request.getAttributeNames().equals("Authorization")) {
		      Map<String, Object> errorDetails = new HashMap<>();
		        errorDetails.put("message", "Invalid token");
		        httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
		        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
		    //    mapper.writeValue(httpServletResponse.getWriter(), errorDetails);
		        httpServletResponse.setStatus(401, "Authorization Required");
		}
		String username = null;
		String jwt = null;
		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			String aesToken = authorizationHeader.substring(7);
			jwt = AESEncryptionConfig.decrypt(aesToken, SECRET_KEY);
			try{
				username = authenticationUtil.extractUserName(jwt);
			}catch(Exception ex) {
			      Map<String, Object> errorDetails = new HashMap<>();
			        errorDetails.put("message", "Invalid token");
			        httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
			        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
			      //  mapper.writeValue(httpServletResponse.getWriter(), errorDetails);
					httpServletResponse.setStatus(401, "Token Expired");
			}
		}
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.userDeatislService.loadUserByUsername(username);
			if (authenticationUtil.validateJWT(jwt, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		filterChain.doFilter(request, httpServletResponse);
	}
}
