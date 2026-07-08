FROM openjdk:17-jdk-slim

# Install Nmap
RUN apt-get update && apt-get install -y nmap

# Create app directory
WORKDIR /app

# Copy JAR file
COPY target/nmap-web-scanner-1.0.0.jar app.jar

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]