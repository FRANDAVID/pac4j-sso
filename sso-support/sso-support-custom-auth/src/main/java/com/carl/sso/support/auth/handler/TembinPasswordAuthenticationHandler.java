package com.carl.sso.support.auth.handler;

import com.carl.sso.support.auth.UsernamePasswordSysCredential;
import org.apereo.cas.adaptors.jdbc.QueryAndEncodeDatabaseAuthenticationHandler;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.configuration.model.support.jdbc.JdbcAuthenticationProperties;
import org.apereo.cas.services.ServicesManager;

import javax.security.auth.login.AccountNotFoundException;
import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;

/**
 * Created by liukx on 2019-01-26.
 */
public class TembinPasswordAuthenticationHandler extends QueryAndEncodeDatabaseAuthenticationHandler {

    private String env;

    public TembinPasswordAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order,DataSource dataSource,JdbcAuthenticationProperties.Encode encode,String env){
        super(name, servicesManager, principalFactory, order,dataSource, encode.getAlgorithmName(),
                encode.getSql(),encode.getPasswordFieldName(),encode.getSaltFieldName(),
                encode.getExpiredFieldName(),encode.getDisabledFieldName(),
                encode.getNumberOfIterationsFieldName(), encode.getNumberOfIterations(),encode.getStaticSalt());
        this.env = env;
    }

    @Override
    protected HandlerResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {
        UsernamePasswordCredential pwdCredential = (UsernamePasswordCredential) credential;
        String username = pwdCredential.getUsername();
        String pwd = pwdCredential.getPassword();

        try {
            Map<String, Object> values = this.getJdbcTemplate().queryForMap(this.sql, username);
        }catch (Exception e){

        }

        return createHandlerResult(credential, this.principalFactory.createPrincipal(((UsernamePasswordSysCredential) credential).getUsername(), Collections.emptyMap()), null);

    }

    @Override
    public boolean supports(Credential credential) {
        return credential instanceof UsernamePasswordCredential;
    }
}
