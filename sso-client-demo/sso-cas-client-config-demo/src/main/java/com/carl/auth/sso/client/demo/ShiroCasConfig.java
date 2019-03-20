package com.carl.auth.sso.client.demo;

//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import com.google.common.collect.Lists;
import com.tembin.member.client.api.AuthTokenApi;
import com.tembin.member.client.api.UserApi;
import com.tembin.shiro.CustomCacheStore;
import com.tembin.shiro.CustomCallbackLogic;
import com.tembin.shiro.CustomCasClient;
import com.tembin.shiro.CustomFormExtractor;
import com.tembin.shiro.CustomLogoutHandler;
import com.tembin.shiro.CustomRestClient;
import com.tembin.shiro.CustomSecurityLogic;
import com.tembin.shiro.RedisCache;
import com.tembin.shiro.RedisCacheManager;
import com.tembin.shiro.RedisSessionDao;
import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.filter.SecurityFilter;
import io.buji.pac4j.realm.Pac4jRealm;
import io.buji.pac4j.subject.Pac4jSubjectFactory;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.mgt.SimpleSessionFactory;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.cas.config.CasProtocol;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.session.J2ESessionStore;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.filter.DelegatingFilterProxy;

@Configuration
public class ShiroCasConfig {
    public ShiroCasConfig() {
    }

    @Bean
    public FilterRegistrationBean filterRegistrationBean() {
        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
        filterRegistration.setEnabled(true);
        filterRegistration.addUrlPatterns(new String[]{"/*"});
        filterRegistration.setOrder(1);
        return filterRegistration;
    }

    @Bean
    public List<AuthorizingRealm> normalRealm() {
        List<AuthorizingRealm> result = Lists.newArrayList();
        Pac4jRealm realm = new Pac4jRealm();
        realm.setPrincipalNameAttribute("casPac4jPrincipal");
        result.add(realm);
        return result;
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomFormExtractor customFormExtractor(CasConfiguration casConfiguration, @Lazy AuthTokenApi authTokenApi, @Lazy UserApi userApi) {
        CustomFormExtractor customFormExtractor = new CustomFormExtractor("phoneNumber", "passwd", "casRestClient");
        customFormExtractor.setConfiguration(casConfiguration);
        customFormExtractor.setAuthTokenApi(authTokenApi);
        customFormExtractor.setUserApi(userApi);
        return customFormExtractor;
    }

    @Bean
    public CasConfiguration casConfiguration(@Value("${spring.cas.prefix_url}") String prefixUrl, @Value("${spring.cas.login_url}") String casLoginUrl, RedisCache cache, DefaultWebSessionManager sessionManager) {
        CasConfiguration casConfiguration = new CasConfiguration(casLoginUrl);
        casConfiguration.setProtocol(CasProtocol.CAS30);
        casConfiguration.setPrefixUrl(prefixUrl);
        casConfiguration.setLogoutHandler(this.defaultCasLogoutHandler(cache, sessionManager));
        return casConfiguration;
    }

    @Bean
    public CustomRestClient casRestFormClient(CasConfiguration casConfiguration, CustomFormExtractor customFormExtractor) {
        CustomRestClient casRestFormClient = new CustomRestClient();
        casRestFormClient.setConfiguration(casConfiguration);
        casRestFormClient.setName("casRestClient");
        casRestFormClient.setCredentialsExtractor(customFormExtractor);
        return casRestFormClient;
    }

    @Bean
    public Clients clients(CustomRestClient customRestClient, CustomCasClient customCasClient) {
        Clients clients = new Clients();
        clients.setClients(new Client[]{customCasClient, customRestClient});
        return clients;
    }

    @Bean
    public Config casConfig(Clients clients) {
        Config config = new Config();
        config.setClients(clients);
        config.setSessionStore(new J2ESessionStore());
        return config;
    }

    @Bean
    public CustomCasClient casClient(CasConfiguration casConfiguration, @Value("${spring.cas.callback_url}") String callbackUrl) {
        CustomCasClient casClient = new CustomCasClient();
        casClient.setConfiguration(casConfiguration);
        casClient.setCallbackUrl(callbackUrl);
        casClient.setName("casClient");
        return casClient;
    }

    @Bean
    public CustomLogoutHandler defaultCasLogoutHandler(RedisCache cache, DefaultWebSessionManager sessionManager) {
        CustomLogoutHandler defaultCasLogoutHandler = new CustomLogoutHandler();
        defaultCasLogoutHandler.setDestroySession(true);
        defaultCasLogoutHandler.setStore(this.customCacheStore(cache));
        defaultCasLogoutHandler.setSessionManager(sessionManager);
        return defaultCasLogoutHandler;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition definition = new DefaultShiroFilterChainDefinition();
        definition.addPathDefinition("/callback", "callback");
        definition.addPathDefinition("/logout", "logout");
        definition.addPathDefinition("/api/v1/message/getCategoryIcon", "anon");
        definition.addPathDefinition("/api/v1/auth/renewToken", "anon");
        definition.addPathDefinition("/api/v1/user/sendCaptcha", "anon");
        definition.addPathDefinition("/api/v1/user/verifyCaptchaAndGetInvitations", "anon");
        definition.addPathDefinition("/api/v1/user/register", "anon");
        definition.addPathDefinition("/api/v1/user/resetPwd", "anon");
        definition.addPathDefinition("/api/v1/user/sendResetPwdCaptcha", "anon");
        definition.addPathDefinition("/api/v1/user/login", "anon");
        definition.addPathDefinition("/api/v1/user/saveUserPosition", "anon");
        definition.addPathDefinition("/api/v1/android/**", "anon");
        definition.addPathDefinition("/api/v1/app/picture/**", "anon");
        definition.addPathDefinition("/api/v2/ios/check", "anon");
        definition.addPathDefinition("/api/v2/review/helper/**", "anon");
        definition.addPathDefinition("/api/v1/mailgun/**", "anon");
        definition.addPathDefinition("/api/v1/internal/call/**", "anon");
        definition.addPathDefinition("/api/member/**", "anon");
        definition.addPathDefinition("/api/user/**", "anon");
        definition.addPathDefinition("/api/auth-token/**", "anon");
        definition.addPathDefinition("/api/base/**", "anon");
        definition.addPathDefinition("/api/account-manager/**", "anon");
        definition.addPathDefinition("/api/account-manager-internal/**", "anon");
        definition.addPathDefinition("/service/**", "anon");
        definition.addPathDefinition("/alipay/**", "anon");
        definition.addPathDefinition("/activity/preorder/**", "anon");
        definition.addPathDefinition("/api/system-feedback/submit-feedback", "anon");
        definition.addPathDefinition("/api/v1/wechat/pay/**", "anon");
        definition.addPathDefinition("/shbank/**", "anon");
        definition.addPathDefinition("/callback/**", "anon");
        definition.addPathDefinition("/3yr/**", "anon");
        definition.addPathDefinition("/account-manager-call-back/**", "anon");
        definition.addPathDefinition("/actuator/**", "anon");
        definition.addPathDefinition("/actuator", "anon");
        definition.addPathDefinition("/error/**", "anon");
        definition.addPathDefinition("/register**", "anon");
        definition.addPathDefinition("/authcode/**", "anon");
        definition.addPathDefinition("/resource/**", "anon");
        definition.addPathDefinition("/public/**", "anon");
        definition.addPathDefinition("/static/**", "anon");
        definition.addPathDefinition("/kamobile/**", "anon");
        definition.addPathDefinition("/tiny-app/*.html", "anon");
        definition.addPathDefinition("/hook/**", "anon");
        definition.addPathDefinition("/**", "user");
        return definition;
    }

    @Bean
    public SubjectFactory subjectFactory() {
        return new Pac4jSubjectFactory();
    }

    @Bean({"shiroRedisCache"})
    public RedisCache cache(@Qualifier("redisTemplate") RedisTemplate redisTemplate) {
        return new RedisCache("redis_", redisTemplate, 1800L);
    }

    @Bean
    public CustomCacheStore customCacheStore(RedisCache cache) {
        return new CustomCacheStore(cache);
    }

    @Bean({"shiroFilter"})
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager, ShiroFilterChainDefinition shiroFilterChainDefinition, Config config, @Value("${spring.cas.default_url}") String defaultUrl) {
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        filterFactoryBean.setSecurityManager(securityManager);
        Map<String, Filter> filters = new HashMap();
        SecurityFilter securityFilter = new SecurityFilter();
        securityFilter.setClients("renewCasClient");
        securityFilter.setConfig(config);
        filters.put("auth", securityFilter);
        SecurityFilter customSecurityFilter = new SecurityFilter();
        customSecurityFilter.setClients("casClient,casRestClient");
        customSecurityFilter.setSecurityLogic(new CustomSecurityLogic());
        customSecurityFilter.setConfig(config);
        filters.put("user", customSecurityFilter);
        CallbackFilter callbackFilter = new CallbackFilter();
        callbackFilter.setConfig(config);
        callbackFilter.setDefaultUrl(defaultUrl);
        callbackFilter.setCallbackLogic(new CustomCallbackLogic());
        filters.put("callback", callbackFilter);
        LogoutFilter logoutFilter = new LogoutFilter();
        logoutFilter.setConfig(config);
        logoutFilter.setCentralLogout(true);
        filters.put("logout", logoutFilter);
        filterFactoryBean.setFilters(filters);
        filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());
        return filterFactoryBean;
    }

    @Bean
    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor getAuthorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor attributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        attributeSourceAdvisor.setSecurityManager(securityManager);
        return new AuthorizationAttributeSourceAdvisor();
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    @Bean({"shiroRedisSessionDao"})
    public RedisSessionDao redisSessionDAO(@Lazy @Qualifier("redisTemplate") RedisTemplate redisTemplate) {
        return new RedisSessionDao(redisTemplate, "redis_shiro_session_", 1800);
    }

    @Bean
    public SimpleSessionFactory simpleSessionFactory() {
        return new SimpleSessionFactory();
    }

    @Bean({"shiroCacheManage"})
    public RedisCacheManager cacheManager(RedisCache redisCache) {
        return new RedisCacheManager(redisCache);
    }

    @Bean
    public DefaultWebSessionManager SessionManager(@Qualifier("shiroCacheManage") RedisCacheManager cacheManager, @Qualifier("shiroRedisSessionDao") RedisSessionDao redisSessionDao, SimpleSessionFactory simpleSessionFactory, @Value("${server.servlet.context-path}") String contextPath) {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionDAO(redisSessionDao);
        sessionManager.setGlobalSessionTimeout(1800000L);
        sessionManager.setCacheManager(cacheManager);
        Cookie cookie = new SimpleCookie();
        cookie.setPath(contextPath);
        cookie.setName("auth-id");
        sessionManager.setDeleteInvalidSessions(true);
        sessionManager.setSessionIdCookie(cookie);
        sessionManager.setSessionFactory(simpleSessionFactory);
        return sessionManager;
    }

    @Bean
    public SecurityManager securityManager(DefaultWebSessionManager sessionManager, @Qualifier("shiroCacheManage") RedisCacheManager cacheManager, List<AuthorizingRealm> realms) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        Cookie cookie = new SimpleCookie("rememberMe");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(604800);
        cookieRememberMeManager.setCookie(cookie);
        securityManager.setRememberMeManager(cookieRememberMeManager);
        securityManager.setRealms(Lists.newArrayList(realms));
        securityManager.setSubjectFactory(this.subjectFactory());
        securityManager.setCacheManager(cacheManager);
        securityManager.setSessionManager(sessionManager);
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setRealms(Lists.newArrayList(realms));
        authenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        securityManager.setAuthenticator(authenticator);
        return securityManager;
    }
}
