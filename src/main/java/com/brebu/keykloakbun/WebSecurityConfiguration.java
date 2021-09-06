package com.brebu.keykloakbun;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuer;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    GenericFilterBean refreshTokenFilter;

    public WebSecurityConfiguration(GenericFilterBean refreshTokenFilter) {
        this.refreshTokenFilter = refreshTokenFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().disable();
        http.addFilterBefore(refreshTokenFilter,  AnonymousAuthenticationFilter.class).authorizeRequests()
                .antMatchers("/api/anonymous","/error", "/instances", "/**/*.css", "/**/img/**", "/**/third-party/**", "/*.js")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login(oauth2 -> oauth2.userInfoEndpoint(
                        userInfo -> userInfo.userService(this.oidcUserService())));
    }


    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oidcUserService() {
        final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        return (userRequest) -> {
            OAuth2User oAuth2User = delegate.loadUser(userRequest);
            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            Jwt jwt = JwtDecoders.fromIssuerLocation(issuer).decode(accessToken.getTokenValue());
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            Map<String, Object> resource;
            Collection<String> resourceRoles;
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            if (resourceAccess != null) {
                resource = (Map<String, Object>) resourceAccess.get(clientId);
                if (resource != null ){
                    resourceRoles = (Collection<String>) resource.get("roles");
                    if(resourceRoles!=null){
                        mappedAuthorities.addAll(resourceRoles.stream()
                                .map(x -> new SimpleGrantedAuthority("ROLE_" + x))
                                .collect(Collectors.toSet()));
                    }
                }
            }

            return new DefaultOAuth2User(mappedAuthorities, oAuth2User.getAttributes(), "preferred_username");

        };
    }
}
