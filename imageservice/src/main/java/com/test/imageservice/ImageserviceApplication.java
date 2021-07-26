package com.test.imageservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@EnableEurekaClient
@SpringBootApplication
public class ImageserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ImageserviceApplication.class, args);
	}

}
