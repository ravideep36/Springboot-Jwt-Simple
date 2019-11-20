package com.example.demo.config;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.services.JwtUserDetailsService;
import com.example.demo.utils.JwtTokenUtil;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	JwtUserDetailsService jwtUserDetailsService;

	@Autowired
	JwtTokenUtil jwtTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String username = null;
		String token = null;
		String requestHeader = request.getHeader("Authorization");
		if (Objects.nonNull(requestHeader) && requestHeader.startsWith("Bearer ")) {

			token = requestHeader.substring(7);
			try {
				username = jwtTokenUtil.getUsernameFromToken(token);
			} catch (IllegalArgumentException e) {
				System.out.println("UNable tojwt token");
			} catch (ExpiredJwtException e) {
				System.out.println("Jwt token has expired.");
			}
			if (Objects.nonNull(username) && SecurityContextHolder.getContext().getAuthentication() == null) {
				UserDetails userDetail = jwtUserDetailsService.loadUserByUsername(username);

				if (jwtTokenUtil.validateToken(token, userDetail)) {
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
							userDetail, null, userDetail.getAuthorities());
					usernamePasswordAuthenticationToken
							.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				}

			}

		}

		filterChain.doFilter(request, response);

	}

}
