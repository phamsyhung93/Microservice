package com.test.galleryservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
@EnableEurekaClient
public class GalleryserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(GalleryserviceApplication.class, args);
	}

}
@Configuration
class RestTemplateConfig{
	@Bean
	@LoadBalanced
	public RestTemplate RestTemplate (){
		return new RestTemplate();
	}
}
