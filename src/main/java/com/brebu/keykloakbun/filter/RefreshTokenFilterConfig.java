package com.brebu.keykloakbun.filter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
public class RefreshTokenFilterConfig {


    @Bean
    GenericFilterBean refreshTokenFilter(OAuth2AuthorizedClientService clientService) {
        return new GenericFilterBean() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) {
                try {
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    if (authentication instanceof OAuth2AuthenticationToken) {
                        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
                        System.out.println(token);
                        System.out.println((String) Objects.requireNonNull(token.getPrincipal().getAttribute("name")));
                        OAuth2AuthorizedClient client =
                                clientService.loadAuthorizedClient(
                                        token.getAuthorizedClientRegistrationId(),
                                        token.getName());
                        if (isAccessTokenExpired(client)) {

                            MultiValueMap<String, String> formParams = getFormParams(client);
                            HttpHeaders httpHeader = getHttpHeader();
                            RequestEntity<MultiValueMap<String, String>> request = getRequest(formParams, httpHeader, client);
                            Map<String, String> responseJson = getResponseJson(request);
                            ClientRegistration clientRegistration = getNewClientRegistration(token, client);
                            OAuth2AccessToken newOauthAccessToken = getNewOauthAccessToken(responseJson);
                            OAuth2RefreshToken newOauth2RefreshToken = getNewOauth2RefreshToken(responseJson);
                            OAuth2AuthorizedClient newAuthorizedClient = getNewAuthorizedClient(clientRegistration,
                                    token, newOauthAccessToken, newOauth2RefreshToken);
                            clientService.saveAuthorizedClient(newAuthorizedClient, authentication);
                        }
                    }

                    filterChain.doFilter(servletRequest, servletResponse);
                } catch (Exception e) {
                    HttpServletRequest req = (HttpServletRequest) servletRequest;
                    HttpServletResponse res = (HttpServletResponse) servletResponse;
                    try {
                        req.logout();
                        res.sendRedirect(req.getRequestURI());
                    } catch (ServletException | IOException servletException) {
                        servletException.printStackTrace();
                        logger.error(e.getMessage());
                    }

                }
            }
        };
    }


    private boolean isAccessTokenExpired(OAuth2AuthorizedClient client) {
        OAuth2AccessToken accessToken = client.getAccessToken();
        return Objects.requireNonNull(accessToken.getExpiresAt()).isBefore(Instant.now());
    }

    private MultiValueMap<String, String> getFormParams(OAuth2AuthorizedClient client) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "refresh_token");
        map.add("refresh_token", Objects.requireNonNull(client.getRefreshToken()).getTokenValue());
        map.add("client_secret", client.getClientRegistration().getClientSecret());
        map.add("client_id", client.getClientRegistration().getClientId());

        return map;
    }

    private HttpHeaders getHttpHeader() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        return httpHeaders;
    }

    private RequestEntity<MultiValueMap<String, String>> getRequest(
            MultiValueMap<String, String> formParams, HttpHeaders httpHeaders,
            OAuth2AuthorizedClient client) {

        return new RequestEntity<>(formParams, httpHeaders, HttpMethod.POST,
                URI.create(client.getClientRegistration().getProviderDetails().getTokenUri()));
    }

    private Map<String, String> getResponseJson(RequestEntity<MultiValueMap<String, String>> requestEntity) {
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(
                requestEntity, new ParameterizedTypeReference<Map<String, String>>() {
                });
        return responseEntity.getBody();
    }

    private ClientRegistration getNewClientRegistration(OAuth2AuthenticationToken token,
                                                        OAuth2AuthorizedClient client) {
        ClientRegistration clientRegistration = client.getClientRegistration();
        ClientRegistration.ProviderDetails providerDetails = clientRegistration.getProviderDetails();
        return ClientRegistration
                .withRegistrationId(token.getAuthorizedClientRegistrationId())
                .clientId(clientRegistration.getClientId())
                .clientSecret(clientRegistration.getClientSecret())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(
                        clientRegistration.getClientAuthenticationMethod().getValue()))
                .authorizationGrantType(new AuthorizationGrantType(
                        clientRegistration.getAuthorizationGrantType().getValue()))
                .redirectUri(clientRegistration.getRedirectUri())
                .scope(clientRegistration.getScopes())
                .authorizationUri(providerDetails.getAuthorizationUri())
                .tokenUri(providerDetails.getTokenUri())
                .userInfoUri(providerDetails.getUserInfoEndpoint().getUri())
                .userNameAttributeName(clientRegistration.getClientName())
                .jwkSetUri(providerDetails.getJwkSetUri())
                .clientName(clientRegistration.getClientName())
                .build();
    }

    private OAuth2AccessToken getNewOauthAccessToken(Map<String, String> responseJson) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                Objects.requireNonNull(responseJson).get("access_token"),
                Instant.now(),
                Instant.now().plus(Integer.parseInt(responseJson.get("expires_in")), ChronoUnit.SECONDS),
                Arrays.stream(responseJson.get("scope").split("\\S")).collect(Collectors.toSet())
        );
    }

    private OAuth2RefreshToken getNewOauth2RefreshToken(Map<String, String> responseJson) {
        return new OAuth2RefreshToken(
                responseJson.get("refresh_token"),
                Instant.now()
        );
    }

    private OAuth2AuthorizedClient getNewAuthorizedClient(ClientRegistration clientRegistration,
                                                          Authentication authentication,
                                                          OAuth2AccessToken newOAuth2AccessToken,
                                                          OAuth2RefreshToken newOAuth2RefreshToken) {
        return new OAuth2AuthorizedClient(
                clientRegistration, authentication.getName(), newOAuth2AccessToken, newOAuth2RefreshToken);
    }
}