package com.example.demo.services;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailsService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		if ("ravideep".equals(username)) {
			return new User("ravideep", "$2a$10$KuHTp27OD4JidoGVHIPJmO8FrQywn/XcGODyPGbwcKf6q1l7AxKLm",
					new ArrayList<>());
		} else {
			throw new UsernameNotFoundException("Username not found");
		}
	}

}
