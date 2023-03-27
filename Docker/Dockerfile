FROM openjdk:18-slim-buster

RUN apt-get update && apt-get install -y git python3
RUN mkdir -p /app

WORKDIR /app

RUN git clone https://github.com/irsdl/IIS-ShortName-Scanner
RUN mv ./IIS-ShortName-Scanner/release/* .
RUN mv ./IIS-ShortName-Scanner/Docker/entrypoint.sh .
RUN chmod +x ./multi_targets.sh ./entrypoint.sh

ARG USERNAME=test
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

RUN chown -R $USERNAME:$USERNAME /app

USER $USERNAME

ENTRYPOINT ["./entrypoint.sh"]
