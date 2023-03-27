FROM openjdk:18-slim-buster

RUN apt-get update && apt-get install -y git python3
RUN git clone https://github.com/irsdl/IIS-ShortName-Scanner
RUN mkdir -p /app
RUN mv ./IIS-ShortName-Scanner/release/* /app/
RUN mv ./IIS-ShortName-Scanner/Docker/entrypoint.sh /app/
WORKDIR /app
RUN chmod +x ./multi_targets.sh ./entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
