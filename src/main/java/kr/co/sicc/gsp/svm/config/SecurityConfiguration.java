package kr.co.sicc.gsp.svm.config;

import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import kr.co.sicc.gsp.svm.gms.common.login.LoginProvider;
import kr.co.sicc.gsp.svm.gms.common.login.SiccUserService;
import kr.co.sicc.gsp.svm.gms.svm.service.SVMLoginProvider;
import kr.co.sicc.gsp.svm.gms.svm.service.SVMSiccUserService;
import kr.co.sicc.gsp.svm.sicc.security.CsrfSecurityRequestMatcher;
import kr.co.sicc.gsp.svm.sicc.security.handler.SiccAccessDeniedHandler;
import kr.co.sicc.gsp.svm.sicc.security.handler.SiccAuthenticationFailureHandler;
import kr.co.sicc.gsp.svm.sicc.security.handler.SiccAuthenticationSuccessHandler;
import kr.co.sicc.gsp.svm.sicc.security.handler.UnauthorizedEntryPoint;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Value("${settings.SICC_LOGIN_URL}")
	String SICC_LOGIN_URL;
	
	@Value("${settings.SICC_SYSTEM}")
	private String SICC_SYSTEM;
	
	@Override
	public void configure(WebSecurity web) throws Exception
	{
		web.ignoring()
			.antMatchers("/resources/**", "/dtds/**", "js/**", "lib/**", 
						 "/css/**", "/images/**", "/font/**", "/favicon.ico", "/**/*.js", 
						 "/**/*.css", "/**/*.json", "/**/*.gif", "/**/*.png");	
		
		// <security:http auto-config="true" use-expressions="true" create-session="never" entry-point-ref="unauthorizedEntryPoint">
	}
	
    @Override
    public void configure(HttpSecurity http) throws Exception 
    {    	
    	http.headers().frameOptions().sameOrigin();
    	http.headers().xssProtection().xssProtectionEnabled(true);
    	http.headers().xssProtection().block(true);
    	
    	http.authorizeRequests()
				.antMatchers( "/test").permitAll()
	    		.antMatchers("/", "/logout", "/login_duplicate", "/access_denied", "/login_fail").permitAll()
	    		.antMatchers("/getSession", "/messageBundle", SICC_LOGIN_URL, "/saml/acs").permitAll()
	    		.antMatchers("/*/svm/common", "/*/svm/main", "/*/svm/about", "/*/svm/volunteer").permitAll()
	    		.antMatchers("/*/svm/contact", "/*/svm/forgotPw", "/*/svm/forgotPwAfter", "/*/svm/chngPw").permitAll()    		
	    		.antMatchers("/svm/user/chngPw", "/*/mail/forgotPw", "/*/svm/user/*").permitAll()    		
	    		.antMatchers("/*/svm/application/*").permitAll()
	    		.antMatchers("/*/svm/application/application", "/*/svm/application/**", "/mail/*").permitAll()	    		
	    		.antMatchers("/*/"+SICC_SYSTEM.toLowerCase()+"/*/view/**", "/changeLocale").permitAll()
	    		.antMatchers("/login_success", "/**").authenticated();

        http.formLogin()
	        	.loginPage(SICC_LOGIN_URL)
	        	.loginProcessingUrl("/loginProcess")
	        	.usernameParameter("id")
	        	.passwordParameter("pw")	        	
	        	.successHandler(siccAuthenticationSuccessHandler()) 
	        	.failureHandler(siccAuthenticationFailureHandler());  
          
        http.sessionManagement()
        		.maximumSessions(1).expiredUrl("/login_duplicate").maxSessionsPreventsLogin(false);
        
        http.logout()
        		.deleteCookies("JSESSIONID");   
        
        http.csrf().requireCsrfProtectionMatcher(new CsrfSecurityRequestMatcher()).and()
        	.exceptionHandling().accessDeniedHandler(siccAccessDeniedHandler());
        
    }
    
    @Bean
    public SiccAuthenticationSuccessHandler siccAuthenticationSuccessHandler() {
    	SiccAuthenticationSuccessHandler bean = new SiccAuthenticationSuccessHandler();
    	bean.setTargetUrlParameter("loginRedirect");  
    	bean.setUseReferer(false);
    	bean.setDefaultUrl("/");    	    	
    	return bean;
    }
    
    @Bean
    public SiccAuthenticationFailureHandler siccAuthenticationFailureHandler() {
    	SiccAuthenticationFailureHandler bean = new SiccAuthenticationFailureHandler();
    	bean.setLoginIdName("id");
    	bean.setLoginPwdName("pw");
    	bean.setLoginRedirectName("loginRedirect");
    	bean.setExceptionMsgName("securityExceptionMsg");
    	bean.setDefaultFailureUrl("/login_fail");
    	return bean;
    }
    
    @Bean
    public SiccAccessDeniedHandler siccAccessDeniedHandler() {
    	SiccAccessDeniedHandler bean = new SiccAccessDeniedHandler();
    	bean.setErrorPage("/access_denied");
    	return bean;
    }
    
    // 占쏙옙占쏙옙 占쏙옙 占싹곤옙占� 
    @Bean 
    public UnauthorizedEntryPoint unauthorizedEntryPoint() {
    	UnauthorizedEntryPoint bean = new UnauthorizedEntryPoint();
    	bean.setRedirect(false);
    	bean.setLoginFormUrl(SICC_LOGIN_URL);
    	bean.setDeniedFwdUrl("/not_login");
    	return bean;
    }

    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
    	auth.authenticationProvider(svmSiccAuthenticationProvider());
    }
    
    @Bean
    public DefaultWebSecurityExpressionHandler DefaultWebSecurityExpressionHandler(){
    	return new DefaultWebSecurityExpressionHandler();
    }
    
    @Bean 
    public SVMSiccUserService svmSiccUserService(){
    	return new SVMSiccUserService();
    }
    
    @Bean
    public SVMLoginProvider svmSiccAuthenticationProvider(){
    	return new SVMLoginProvider();
    }
    
    @Bean
    public SiccUserService siccUserService(){
    	return new SiccUserService();
    }
    
    @Bean
    public LoginProvider siccAuthenticationProvider(){
    	return new LoginProvider();
    }
    
    @Bean
    public ShaPasswordEncoder shaPasswordEncoder(){
    	ShaPasswordEncoder shaPasswordEncoder = new ShaPasswordEncoder(256);
    	shaPasswordEncoder.setEncodeHashAsBase64(true);
    	return shaPasswordEncoder;
    }
    
    @Bean
    public ReflectionSaltSource reflectionSaltSource(){
    	ReflectionSaltSource reflectionSaltSource = new ReflectionSaltSource();
    	reflectionSaltSource.setUserPropertyToUse("salt");
    	return reflectionSaltSource;
    }  

}
