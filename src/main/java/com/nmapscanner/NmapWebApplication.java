package com.nmapscanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class NmapWebApplication {
    public static void main(String[] args) {
        SpringApplication.run(NmapWebApplication.class, args);
        System.out.println("🌐 Nmap Web Scanner started!");
        System.out.println("📍 Open: http://localhost:8080");
    }
}