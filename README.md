# Spring Security OAuth2.0 + JWT 인증

이 프로젝트는 Spring Security, OAuth2.0 및 JWT(JSON Web Tokens)를 사용한 안전한 인증 및 권한 부여 메커니즘을 시연합니다.

## 목차

- [소개](#소개)
- [특징](#특징)
- [아키텍처](#아키텍처)
- [기술 스택](#기술-스택)
- [설정](#설정)
- [API 엔드포인트](#api-엔드포인트)

## 소개

이 프로젝트는 Spring Security와 OAuth2.0 및 JWT를 통합하여 강력하고 확장 가능한 인증 시스템을 구현합니다.

## 특징

- **JWT 기반 인증**: 토큰을 통해 사용자의 인증 및 권한 부여를 관리합니다.
- **OAuth2.0 통합**: 외부 인증 제공자와의 원활한 통합을 지원합니다.
- **Spring Security**: 다양한 보안 기능을 활용한 강력한 보안 프레임워크입니다.

## 아키텍처

- **Spring Boot**: 애플리케이션의 기반 프레임워크
- **Spring Security**: 보안 및 인증 관리
- **OAuth2.0**: 인증 및 권한 부여 프로토콜
- **JWT**: JSON Web Tokens을 사용한 인증 토큰

## 기술 스택

- Java 17
- Spring Boot 3.x
- Spring Security 6.x
- Spring OAuth2
- JWT

## 설정

`application.yml` 또는 `application.properties` 파일을 생성하여 다음과 같이 설정합니다:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: your-client-id
            client-secret: your-client-secret
            scope: profile, email
        provider:
          google:
            authorization-uri: https://accounts.google.com/o/oauth2/auth
            token-uri: https://oauth2.googleapis.com/token
            user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
            user-name-attribute: sub

jwt:
  secret: your-jwt-secret
  expiration-time: 3600000 # 1 hour in milliseconds
