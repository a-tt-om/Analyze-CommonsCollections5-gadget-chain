package com.java.insecure_deserialization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class InsecureDeserializationApplication {

	public static void main(String[] args) {
		SpringApplication.run(InsecureDeserializationApplication.class, args);
	}

}
