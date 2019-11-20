package com.example.demo.utils;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7255131479553176776L;
	@Value("${jwt.secret}")
	private String secret;

	private static final long JWT_TOKEN_VALIDITY = 60 * 60 * 5;

	public String getUsernameFromToken(String token) {
		return getClaimsFromToken(token, Claims::getSubject);
	}

	public Date getIssuerDateFromToken(String token) {
		return getClaimsFromToken(token, Claims::getIssuedAt);
	}

	public Date getExpirationDatefromToken(String token) {
		return getClaimsFromToken(token, Claims::getExpiration);
	}

	public boolean isTokenExpired(String token) {
		return getExpirationDatefromToken(token).before(new Date());
	}

	public boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

	}

	public <T> T getClaimsFromToken(String token, Function<Claims, T> claimResolver) {
		Claims claims = getAllClaimsFromToken(token);
		return claimResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}
	
	public String generateToken(UserDetails userDetail) {
		Map<String,Object> claim = new HashMap<String, Object>();
		return doGenerateToken(claim, userDetail.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claim, String subject) {
		return Jwts.builder().setClaims(claim).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

}
