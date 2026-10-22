# Build the jar first:  mvn -f reference-system/pom.xml -DskipTests install
# One image, many services: the ENTRYPOINT is `java` with the classpath; each
# compose service picks its main class via `command:`.
FROM eclipse-temurin:25-jre
WORKDIR /app
COPY target/reconmail-api.jar /app/reconmail-api.jar
COPY target/lib /app/lib
ENTRYPOINT ["java", "-cp", "/app/reconmail-api.jar:/app/lib/*"]
CMD ["com.reconmail.api.ApiMain", "8080"]
