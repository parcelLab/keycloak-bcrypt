ARG keycloak_version

FROM quay.io/keycloak/keycloak:${keycloak_version}

ARG keycloak_bcrypt_version=1.5.6

COPY ./keycloak-bcrypt-${keycloak_bcrypt_version}.jar /opt/keycloak/providers/
