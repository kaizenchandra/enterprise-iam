FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /src
COPY . .
RUN mvn -B -DskipTests package
FROM eclipse-temurin:21-jre
ARG MODULE=iam-server
WORKDIR /app
COPY --from=build /src/${MODULE}/target/${MODULE}-0.1.0-SNAPSHOT.jar app.jar
RUN mkdir /keys && chown 10001:10001 /keys
USER 10001:10001
EXPOSE 9000
ENTRYPOINT ["java","-XX:MaxRAMPercentage=70","-jar","/app/app.jar"]
