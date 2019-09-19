package org.activiti;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;


@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication()
					.withUser("admin")
					.password("{noop}admin").authorities("ROLE_ACTIVITI_ADMIN","ROLE_ACTIVITI_USER").roles("ACTIVITI_USER");
		}


	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable()
					.authorizeRequests()
					.antMatchers("/**").hasRole("ACTIVITI_USER")
					.and().httpBasic().realmName("MY_TEST_REALM")
					.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	    }

}

