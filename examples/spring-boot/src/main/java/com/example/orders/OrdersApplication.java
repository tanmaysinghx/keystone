package com.example.orders;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class OrdersApplication {

    public static void main(String[] args) {
        SpringApplication.run(OrdersApplication.class, args);
    }

    /** Shows which values arrived from Keystone, without ever printing a secret. */
    @Bean
    CommandLineRunner show(
            @Value("${spring.datasource.url}") String url,
            @Value("${spring.datasource.password}") String password,
            @Value("${orders.payment-gateway}") String gateway,
            @Value("${orders.retry-limit}") int retryLimit) {
        return args -> {
            System.out.println("KEYSTONE-CHECK spring.datasource.url=" + url);
            System.out.println("KEYSTONE-CHECK spring.datasource.password=<" + password.length() + " chars>");
            System.out.println("KEYSTONE-CHECK orders.payment-gateway=" + gateway);
            System.out.println("KEYSTONE-CHECK orders.retry-limit=" + retryLimit);
        };
    }
}
