package kr.co.sicc.gsp.svm.config;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.servlet.Filter;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.resource.PathResourceResolver;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import kr.co.sicc.gsp.svm.gms.common.interceptor.BasicInfoInterceptor;
import kr.co.sicc.gsp.svm.gms.common.interceptor.SiccPagePresetInterceptor;
import kr.co.sicc.gsp.svm.sicc.session.SerializableResourceBundleMessageSource;


@Configuration
@EnableWebMvc
public class WebMvcConfiguration extends WebMvcConfigurerAdapter{
	
	private static final String[] RESOURCE_LOCATIONS = {"classpath:/static/"};
	
	@Value("${settings.SICC_SYSTEM}")
	String SICC_SYSTEM;
	
    /**
     * application.yml에서 생성한 데이터 소스 빈 등록
     * @return
     */
    @Bean
    @ConfigurationProperties(prefix="spring.datasource")
    public DataSource dataSource() {
        return DataSourceBuilder.create().build();
    }
    
    /**
     * 트랜젝션 메니저 등록
     * @return
     */
    @Bean
    public DataSourceTransactionManager txManager() {
        return new DataSourceTransactionManager(dataSource());
    }    
    
    @Autowired
    SiccPagePresetInterceptor siccPagePresetInterceptor;
    
    @Autowired
    BasicInfoInterceptor basicInfoInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {    	
    	String system_Pattern = "/*/"+SICC_SYSTEM.toLowerCase()+"/**";
    	
        registry.addInterceptor(siccPagePresetInterceptor)        
                .addPathPatterns("/*/cfs/**")
        		.addPathPatterns(system_Pattern)
        		.excludePathPatterns("/js/**")
        		.excludePathPatterns("/css/**")
        		.excludePathPatterns("/images/**")
        		.excludePathPatterns("/dtds/**")
        		.excludePathPatterns("/font/**")
        		.excludePathPatterns("/resources/**")        		
        		.excludePathPatterns("/link_files/**");   		
        
        registry.addInterceptor(basicInfoInterceptor);
                	
        
        // 다국어 지원
        //registry.addInterceptor(localeChangeInterceptor());
        // -> RequestMappingHandlerMapping으로 인터셉터 구현
    }   

    @Override
    public void addResourceHandlers(final ResourceHandlerRegistry registry) {
        if (!registry.hasMappingForPattern("/**")) {
            registry
            	.addResourceHandler("/**")
            	.addResourceLocations(RESOURCE_LOCATIONS)
            	.setCachePeriod(3600)
            	.resourceChain(true)
            	.addResolver(new PathResourceResolver());            	
          }
//        //registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");
//        //registry.addResourceHandler("/link_files/**").addResourceLocations("/link_files/");
//        registry.addResourceHandler("/js/**").addResourceLocations("/js/").addResourceLocations(RESOURCE_LOCATIONS);
//        registry.addResourceHandler("/css/**").addResourceLocations("/css/").addResourceLocations(RESOURCE_LOCATIONS);
//        registry.addResourceHandler("/font/**").addResourceLocations("/font/").addResourceLocations(RESOURCE_LOCATIONS);
//        //registry.addResourceHandler("/dtds/**").addResourceLocations("/dtds/");
//        registry.addResourceHandler("/images/**").addResourceLocations("/images/").addResourceLocations(RESOURCE_LOCATIONS);               
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // View의 종류 : 1.BeanNAmeViewResolver 2.UrlBasedViewResolver 3.InternalResourceViewResolver
    // 1번 BeanNameViewResolver는 스프링 컨테이너에 Bean으로 등록된 View를 이름으로 찾아 사용하는 Resolver이다.
    // 2번 UrlBasedViewResolver는 반환값과 매칭되는 url을 찾아 view를 매핑하는 Resolver이다. 흔히 이 Resolver는 TilesView클래스를 setViewClass()하여 사용된다.
    // 3번 InternalResourceViewResolver는 2번과 비슷하지만 찾는 대상이 Resource이다. 정적인 자원 즉 webapp하위의 자원들을 반환값으로 찾게 되는데 흔히 setPrefix와 setSuffix를 사용하여 "/" 와 ".jsp" 를 생략할 수 있다. setViewClass는 JstlView.class를 사용한다.
    // 실제로 Spring Boot 환경에서 별다른 설정 안하면 json 이 기본
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    @Bean
    public ViewResolver contentNegotiatingViewResolver(ContentNegotiationManager manager) {    	
    	List<View> defaultViews = new ArrayList<View>();
    	MappingJackson2JsonView jsonView = new MappingJackson2JsonView();
    	defaultViews.add(jsonView);
    	
    	ContentNegotiatingViewResolver resolver = new ContentNegotiatingViewResolver();
    	resolver.setOrder(1);
    	resolver.setContentNegotiationManager(manager);
    	resolver.setDefaultViews(defaultViews);

    	return resolver;
    }
    
    /**
     * 기본 리졸버
     * @return
     */    
    @Bean
    public ViewResolver internalResourceViewResolver() {
        InternalResourceViewResolver bean = new InternalResourceViewResolver();
        bean.setViewClass(JstlView.class);
        bean.setPrefix("/WEB-INF/views/");
        bean.setSuffix(".jsp");
        bean.setContentType("text/html; charset=UTF-8");
        bean.setOrder(2); // internalResourceViewResolver를 2순위로 둔다. 
        return bean;
    }
    
    /**
     * 예죄처리 리졸버
     * @return
     */    
    @Bean
    public SimpleMappingExceptionResolver simpleMappingExceptionResolver() {
    	SimpleMappingExceptionResolver bean = new SimpleMappingExceptionResolver();
    	bean.setOrder(1);  
    	bean.setDefaultErrorView("common/error/error");
    	bean.setExceptionMappings(getExceptionProperties());    	
    	return bean;
    }
	private Properties getExceptionProperties()
	{
		Properties properties = new Properties();
		properties.setProperty("BusinessLogicException", "common/error/500");
		properties.setProperty("RuntimeException", "common/error/500");
		properties.setProperty("TypeMismatchException", "common/error/500");
		properties.setProperty("NoSuchRequestHandlingMethodException", "common/error/500");		
		return properties;
	}
     	
    /**
     * 다국어 지원 설정
     * @return
     */   
    @Bean
    public SerializableResourceBundleMessageSource messageSource() {
    	SerializableResourceBundleMessageSource source = new SerializableResourceBundleMessageSource();
    	String system_message = "classpath:i18n/messages/"+SICC_SYSTEM.toLowerCase()+"Message";
        // resource 밑에 해당 폴더에서 properties를 찾는다.        
        source.setBasenames("classpath:i18n/messages/globalMessage", system_message, "classpath:i18n/messages/cfsMessage", "classpath:i18n/messages/sysMessage");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return source;
    }	
    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
    	LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
		localeChangeInterceptor.setParamName("lang"); //request로 넘어오는 language parameter를 받아서 locale로 설정 한다.
		return localeChangeInterceptor;
    }
    @Bean
    public SessionLocaleResolver localeResolver() {    	
		SessionLocaleResolver localeResolver = new SessionLocaleResolver(); //세션 기준으로 로케일을 설정 한다.
        //Locale defaultLocale = new Locale("en"); //최초 기본 로케일을 강제로 설정이 가능 하다.
        //localeResolver.setDefaultLocale(defaultLocale);
        return localeResolver;
    }         
    
    @Bean    
    public RequestMappingHandlerMapping handlerMapping() {
    	// addInterceptors().addInterceptor 함수에 다국어지원 Interceptor를 추가 하는 대신 우선순위가 높은 handler에 적용
	    RequestMappingHandlerMapping rm = new RequestMappingHandlerMapping();
	    rm.setInterceptors(localeChangeInterceptor());
	    return rm;
    }

	@Override
	public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}

	@Bean
	public InternalResourceViewResolver viewResolver() {
		InternalResourceViewResolver resolver = new InternalResourceViewResolver();
		resolver.setPrefix("/WEB-INF/views/");
		resolver.setSuffix(".jsp");
		return resolver;
	}
	
	@Bean
	public HttpMessageConverter<String> responseBodyConverter(){
		return new StringHttpMessageConverter(Charset.forName("UTF-8"));
	}
	
	@Bean
	public Filter characterEncodinfFilter(){
		CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
		characterEncodingFilter.setEncoding("UTF-8");
		characterEncodingFilter.setForceEncoding(true);
		return characterEncodingFilter;
	}
	
}