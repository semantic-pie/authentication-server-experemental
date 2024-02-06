FROM amazoncorretto:17-alpine-jdk

WORKDIR /app

COPY build/libs/resources-server-0.0.1-SNAPSHOT.jar /app/resources-server.jar

EXPOSE 8080

CMD ["java", "-jar", "resources-server.jar"]
