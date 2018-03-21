package kr.co.sicc.gsp.svm.gms.common.interceptor;

import java.io.IOException;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import kr.co.sicc.gsp.svm.gms.common.login.UserInfo;
import kr.co.sicc.gsp.svm.gms.common.sso.SSOProvider;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.util.GMSXssUtil;

@Component
public class SiccPagePresetInterceptor extends HandlerInterceptorAdapter{
	
	@Autowired
	@Resource(name="sqlSession")
	SqlSession sql_session;

	// kimjw sso
	//@Resource(name="SICC_SSO")
	@Value("${settings.SICC_SSO}")
	private Boolean SICC_SSO;
	
	//@Resource(name="SICC_SYSTEM")
	@Value("${settings.SICC_SYSTEM}")
	private String SICC_SYSTEM;

	//@Resource(name="SICC_XSS_FILTER")
	@Value("${settings.SICC_XSS_FILTER}")
	private Boolean SICC_XSS_FILTER;
	
	@Value("${security.oauth2.client.client-id}")
	private String CLIENT_ID;

	@Value("${security.oauth2.client.client-secret}")
	private String CLIENT_SECRET;
	
	@Value("${security.oauth2.client.check-token-uri}")
	private String CHECK_TOKEN_URI;
	
	/**
	 * This implementation always returns {@code true}.
	 */
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
		throws Exception {
		Object obj = ((HandlerMethod)handler);
		RequestMapping rm = ((HandlerMethod)obj).getMethodAnnotation(RequestMapping.class);
		
		System.out.println("SiccPagePresetInterceptor >>>> rm : " + rm);
		
		if(rm != null){
			
			// 2017-07-18 kimjw: Xssfilter 추가 
			if (SICC_XSS_FILTER) {
				if (xssFilter(request, response)) {
					
					String accept = request.getHeader("accept");

			        if ( StringUtils.indexOf(accept, "application/json") > -1 ) {
			        	response.sendRedirect("/xss_req_json");
			        } else {					
						String referer = request.getHeader("referer");
						request.setAttribute("_request_url", referer);
						//response.sendRedirect("/xss_req"); 
						request.getRequestDispatcher("/xss_req").forward(request, response);
						return false;	
			        }
				}
			}
			// 쿠키 체크 및 리다렉트
			if(SICC_SSO) {
				String uri = request.getRequestURI();
				Pattern regx = Pattern.compile("^\\/.*\\/"+SICC_SYSTEM.toLowerCase()+"\\/.*\\/view\\/.*$");
				Matcher m = regx.matcher(uri);
				Pattern regx2 = Pattern.compile("^\\/.*\\/"+SICC_SYSTEM.toLowerCase()+"\\/common$");
				Matcher m2 = regx2.matcher(uri);
				boolean matches = m.matches();
				boolean matches2 = m2.matches();
				
				System.out.println("uri : "+uri);
				System.out.println("matches : "+matches);
				
				if(!matches && !matches2) {
					boolean chkCookie = SSOProvider.checkCookies(request);					
					System.out.println("checkCookies : "+chkCookie);
					
					if(chkCookie) {
						System.out.println("updateCookies ...");
						if(!request.getParameterMap().containsKey("firstUser")) {
							HttpSession session = request.getSession();
							UserInfo user = (UserInfo)session.getAttribute("userInfo");
							if(user.getSso_msg().equals("login.user.notfound")) {
								response.sendRedirect("/");
							} else if(user.getAuthorities().isEmpty()) {
								response.sendRedirect("/");
							}
						}
						SSOProvider.updateCookies(request, response);
					} else {
						response.sendRedirect("/login_duplicate");
						return true;
					}
				}
			}
			
			String uri = request.getRequestURI();
			String controlUrl = "";
			String lang = null;
			
			Pattern regx = Pattern.compile("/in/");
			Matcher m = regx.matcher(uri);
			
			while(m.find()){
				controlUrl = uri.substring(m.end()-1);
				lang = uri.substring(m.start()+1, m.end()-1);
			}
			if( !"in".equalsIgnoreCase(lang) ){
				lang = "en";
			}					
			
//			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//			UserInfo user = null;
//			if(auth != null && auth.getPrincipal() != null && !"anonymousUser".equals(String.valueOf(auth.getPrincipal()))){
//				user = (UserInfo)SecurityContextHolder.getContext().getAuthentication().getDetails();
//			}
			
			HttpSession session = request.getSession();
			Locale locales = null;
			String session_lang = String.valueOf(session.getAttribute(SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME));
			
			if(null != session_lang && !"null".equals(session_lang) && !"".equals(session_lang)){
				if(!lang.equals(session_lang)){
					if(null != lang && "en".equalsIgnoreCase(lang)){
						locales = Locale.ENGLISH;
					}else{
						locales = new Locale("in");
					}
					session.setAttribute(SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME, locales);
				}
			}else{
				if(null != lang && "en".equalsIgnoreCase(lang)){
					locales = Locale.ENGLISH;
				}else{
					locales = new Locale("in");
				}
				session.setAttribute(SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME, locales);
			}
			
//			CFSActiveDAO mapper = session.getMapper(CFSActiveDAO.class);
//			mapper.writeHistory(user.getCurrent_system_cd(), controlUrl, user.getUsername(), user.getUser_ip());
			
			// for 2018 SaaS
//			boolean isCheckToken = true;
//			if((SVMUserVO) session.getAttribute("userInfo") != null && session.getAttribute("oauth2AccessToken") != null) {
//				isCheckToken = getOAuth2CheckToken(request);
//			}
//		
//			// oauth2 token이 유효하지 않다면
//			if(!isCheckToken) {
//				response.sendRedirect("/");
//			}
			//-- for 2018 SaaS
			
		}
		return true;
	}
	
	// XssFilter
	public boolean xssFilter(HttpServletRequest request, HttpServletResponse response){
		boolean isInclude = false;
				
		String content_type = request.getContentType();
		boolean multipart_yn = false;
		if(content_type != null && content_type.indexOf("multipart/form-data") > -1){
			multipart_yn = true;
		}
		
		if(request != null){
			Entry<String, ? extends Object> obj = null;

			for (Object ele : request.getParameterMap().entrySet()) {
				obj = (Entry<String, ? extends Object>) ele;
				//int i = 0;
				if (obj.getValue() instanceof String[]) {
					for (String param : (String[]) obj.getValue()) {
						if (GMSXssUtil.validateXss(param) == false) {
							// 필요시 xss 필터링 문자 초기화
							//((String[]) obj.getValue())[i] = ""; 
							isInclude = true;
						}
						//i++;
					}
				}
			}
		}
				
		return isInclude;
	}
	
	// oauth2 token 유효성 체크 
	public boolean getOAuth2CheckToken(HttpServletRequest request) {
		
		HttpSession session = request.getSession();
		if((SVMUserVO) session.getAttribute("userInfo") != null && session.getAttribute("oauth2AccessToken") == null) {
			return false;
		}
		
		String clientCredentials = CLIENT_ID + ":" + CLIENT_SECRET;
		String base64ClientCredentials = new String(Base64.encodeBase64(clientCredentials.getBytes()));
		
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.set("Accept", "application/json");
		headers.add("Authorization", "Basic " + base64ClientCredentials);		
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("token", (String)session.getAttribute("oauth2AccessToken"));
		
		RestTemplate restTemplate = new RestTemplate();
		HttpEntity<MultiValueMap<String,String>> requestEntity = new HttpEntity<>(params, headers);
		restTemplate.getMessageConverters().add(new FormHttpMessageConverter());
		restTemplate.setErrorHandler(new ResponseErrorHandler() {
			@Override
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return false;
			}
			
			@Override
			public void handleError(ClientHttpResponse response) throws IOException {				
			}			
		});		
		
		URI url = URI.create(CHECK_TOKEN_URI);
		try {
			ResponseEntity<Map> response = restTemplate.postForEntity(url, requestEntity, Map.class);		
			if(response.getStatusCode().value() == 200) {
				return true;				
			}				
		} catch (HttpStatusCodeException exception) {
			int statusCode = exception.getStatusCode().value();			
		}
		return false;
	}
}
