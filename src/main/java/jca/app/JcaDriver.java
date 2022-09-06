package jca.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan(basePackages= {"jca"})
@SpringBootApplication
public class JcaDriver  {
	
	public static void main(String[] args) {
		SpringApplication.run(JcaDriver.class);
		System.out.println("bouncycastle");
	}

}
