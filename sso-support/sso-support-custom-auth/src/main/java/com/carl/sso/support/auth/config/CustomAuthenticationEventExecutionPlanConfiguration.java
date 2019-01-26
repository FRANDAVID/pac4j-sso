/*
 * 版权所有.(c)2008-2017. 卡尔科技工作室
 */


package com.carl.sso.support.auth.config;

import com.carl.sso.support.auth.handler.TembinPasswordAuthenticationHandler;
import com.carl.sso.support.auth.handler.UsernamePasswordSystemAuthenticationHandler;
import com.mysql.jdbc.Driver;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.jdbc.JdbcAuthenticationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashSet;

/**
 * @author Carl
 * @date 2017/10/23
 * @since 1.6.0
 */
@Configuration("customAuthenticationEventExecutionPlanConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CustomAuthenticationEventExecutionPlanConfiguration implements AuthenticationEventExecutionPlanConfigurer {

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    @Autowired
    @Qualifier("jdbcPrincipalFactory")
    public PrincipalFactory jdbcPrincipalFactory;
    @Autowired
    private CasConfigurationProperties casProperties;
    @Autowired
    @Qualifier("mysqlDataSource")
    private DataSource dataSource;
    @Value("${env}")
    private String env;

    @Bean
    public DataSource mysqlDataSource() throws SQLException{
        JdbcAuthenticationProperties.Encode encode=casProperties.getAuthn().getJdbc().getEncode().get(0);
        SimpleDriverDataSource dataSource = new SimpleDriverDataSource(new Driver(),encode.getUrl(),encode.getUser(),encode.getPassword());
        return dataSource;
    }

    /**
     * @description 一个AuthenticationEventExecutionPlanConfigurer注入多个handler,需要用集合,每个AuthenticationHandler都使用@bean的卡,启动会卡住
     * @author liukx
     * @date 2019-01-26
     */
    @Bean
    public Collection<AuthenticationHandler> diyAuthenticationHandlers() {
        Collection<AuthenticationHandler> handlers = new HashSet<>();
        handlers.add(customAuthenticationHandler());
        handlers.add(tembinPasswordAuthenticationHandler());
        return handlers;
    }

    /**
     * 坑:每个AuthenticationHandler都使用@bean的卡,启动会卡住
     *
     * @return
     */
//    @Bean
    public AuthenticationHandler customAuthenticationHandler() {
        //优先验证,order=1
        AuthenticationHandler handler = new UsernamePasswordSystemAuthenticationHandler(
                "customAuthenticationHandler", servicesManager, jdbcPrincipalFactory, 1);
        return handler;
    }

//    @Bean
    public AuthenticationHandler tembinPasswordAuthenticationHandler() {
        JdbcAuthenticationProperties.Encode encode=casProperties.getAuthn().getJdbc().getEncode().get(0);
        AuthenticationHandler handler = new TembinPasswordAuthenticationHandler("tembinAuthenticationHandler",
                servicesManager, jdbcPrincipalFactory, 10,dataSource,encode,env);
        return handler;
    }

    //注册自定义认证器
    @Override
    public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
        CustomAuthenticationEventExecutionPlanConfiguration.this.diyAuthenticationHandlers().forEach((h) -> {
            plan.registerAuthenticationHandler(h);
        });
//        plan.registerAuthenticationHandler(customAuthenticationHandler());
//        plan.registerAuthenticationHandler(tembinPasswordAuthenticationHandler());

    }
}
