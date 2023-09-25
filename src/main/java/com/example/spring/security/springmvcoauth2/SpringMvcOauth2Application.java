package com.example.spring.security.springmvcoauth2;

import com.example.spring.security.springmvcoauth2.config.SecurityConfig;
import com.example.spring.security.springmvcoauth2.config.WebConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({SecurityConfig.class, WebConfig.class})
public class SpringMvcOauth2Application {

	public static void main(String[] args) {
		SpringApplication.run(SpringMvcOauth2Application.class, args);
	}

}
