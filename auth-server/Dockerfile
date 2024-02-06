FROM amazoncorretto:17-alpine-jdk

WORKDIR /app

COPY build/libs/auth-server-0.0.1-SNAPSHOT.jar /app/auth-server.jar

EXPOSE 8080

CMD ["java", "-jar", "auth-server.jar"]
