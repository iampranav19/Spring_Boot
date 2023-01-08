package com.example.demo;

import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityLatest {

	@Bean
	public UserDetailsService detailsService() {
		
		UserDetails build = org.springframework.security.core.userdetails.User.withUsername("pranav")
				.password(encoder().encode("test123"))
				.roles("ADMIN")
				.build();
		UserDetails build2 = org.springframework.security.core.userdetails.User.withUsername("naman")
				.password(encoder().encode("demo123"))
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(build,build2);

	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
	{
		return http.authorizeRequests()
			.antMatchers("/home").permitAll()
			.and()
			.authorizeRequests()
			.antMatchers("/welcome","/greet")
			.authenticated()
			.and()
			.httpBasic()
			.and()
			.build();
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

}
