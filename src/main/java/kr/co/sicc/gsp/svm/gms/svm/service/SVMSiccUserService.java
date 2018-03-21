package kr.co.sicc.gsp.svm.gms.svm.service;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.ibatis.session.SqlSession;
import org.omg.CORBA.portable.ApplicationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import kr.co.sicc.gsp.svm.gms.common.interceptor.BasicInfo;
import kr.co.sicc.gsp.svm.gms.common.login.Role;
import kr.co.sicc.gsp.svm.gms.svm.dao.SVMLoginDAO;
import kr.co.sicc.gsp.svm.gms.svm.dao.SVMUserDAO;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.common.SiccMessageUtil;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;

@Service
public class SVMSiccUserService implements UserDetailsService{
		
	@Autowired
	@Resource(name="sqlSession")
	private SqlSession sqlSession;

	//@Resource(name="SICC_SSO")
	@Value("${settings.SICC_SSO}")
	private Boolean SICC_SSO;

	@Value("${settings.SICC_SYSTEM}")
	private String SICC_SYSTEM;
	
	// client_id : Oauth2 인증을 위한 정보
	@Value("${security.oauth2.client.client-id}")
	private String CLIENT_ID;

	// client_secret : Oauth2 인증을 위한 정보
	@Value("${security.oauth2.client.client-secret}")
	private String CLIENT_SECRET;

	@Value("${security.oauth2.client.access-token-uri}")
	private String ACCESS_TOKEN_URI;
	
	// for 2018 SaaS
	@Override
	public SVMUserVO loadUserByUsername(String email) throws UsernameNotFoundException {
		SVMLoginDAO mapper = sqlSession.getMapper(SVMLoginDAO.class);

		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		HttpSession session = request.getSession();
		BasicInfo bInfo = (BasicInfo)session.getAttribute("BasicInfo");
		String tenantId = "";
		String cpcd = "";
		if(bInfo != null) {	
			tenantId = bInfo.getTenant_id();
			cpcd = bInfo.getCp_cd();
		}
		SVMUserVO user = mapper.userInfo(tenantId, cpcd, email);
		
		///////////////////////////////////////		
		if(user == null) {
			throw new UsernameNotFoundException("svm.info.msg.no_regi_email");
		}
		
		////////////////////////사용 가능하도록 강제 설정
		user.setEnabled(true);
		////////////////////				
		if(!user.isEnabled()){
			throw new BadCredentialsException("sys.user.message.disabled_user");
		}

		List<? extends Role> roles = mapper.authList(tenantId, cpcd, email);
		user.setAuth(roles);
		user.setUser_ip(getClientIp(request));
		
		return user;
	}
	
	/*
	@Override
	public SVMUserVO loadUserByUsername(String email) throws UsernameNotFoundException {
		SVMLoginDAO mapper = session.getMapper(SVMLoginDAO.class);
		SVMUserVO user = mapper.userInfo(email);
		if(user == null) {
			if(SICC_SSO) {
				user = new SVMUserVO();
				user.setEmail(email);
				user.setSso_msg("login.user.notfound");
				
				return user;
			} else {
				throw new UsernameNotFoundException("svm.info.msg.no_regi_email");
			}
		}
		
//		if(user == null)
//            throw new UsernameNotFoundException("User not found: " + email);
		
		if(!user.isEnabled()){
			throw new BadCredentialsException("sys.user.message.disabled_user");
		}
		
//		if(user.getLoginFailCnt() >= 10){
//		
//			String flag = mapper.calculateLoginFailResetCriterion(email);
//			if(flag != null && flag.equals("Y")){
//				//user.setCurrent_system_cd(SICC_SYSTEM);
//				mapper.loginFailCountReset(user);
//			}else{
//				throw new BadCredentialsException("login.access.denied_failcnt");
//			}
//		}
		
		List<? extends Role> roles = mapper.authList(email);
		user.setAuth(roles);
		
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		user.setUser_ip(getClientIp(request));
//		user.setCurrent_system_cd(SICC_SYSTEM);
		
		return user;
	}
	*/
	public int loginSuccess(SVMUserVO SVMUserVO) {
//		int result = mapper.loginSuccess(SVMUserVO);
		int result = 0;
//		result = mapper.loginFailCountReset(SVMUserVO);		
		
		return result;
	}

	public int loginFail(SVMUserVO SVMUserVO) {
//		SVMLoginDAO mapper = session.getMapper(SVMLoginDAO.class);
		//HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
//		SVMUserVO.setUser_ip(getClientIp(request));
//		SVMUserVO.setCurrent_system_cd(SICC_SYSTEM);
//		int result = mapper.loginFail(SVMUserVO);
		int result = 0;
//		result = mapper.loginFailCount(SVMUserVO);
//		
		return result;
	}

	public int logout(SVMUserVO SVMUserVO) {
		//SVMLoginDAO mapper = session.getMapper(SVMLoginDAO.class);
		//int result = mapper.logout(SVMUserVO);
		int result = 0;
		
		return result;
	}

	public SVMUserVO getSVMUserVO(String username) {		
		SVMLoginDAO mapper = sqlSession.getMapper(SVMLoginDAO.class);
		//SVMUserVO user = mapper.userInfo(username);
		//parameter/항목추가
				String tenantId = "test1";
				String cpcd = "test1";
				SVMUserVO user = mapper.userInfo(username, tenantId, cpcd);
		
		if(user != null) {
			HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
			user.setUser_ip(getClientIp(request));
//			user.setCurrent_system_cd(SICC_SYSTEM);
		}
		
		return user;
	}

	// kimjw sso
	public Authentication authenticate_acs(SVMUserVO samluser) throws AuthenticationException {

		try {
			String user_id = samluser.getUsername();		
			SVMUserVO user;
			Collection<? extends Role> authorities = null;
		    
			user = loadUserByUsername(user_id);
						
			if(!user.getSso_msg().equals("login.user.notfound")) {
				authorities = user.getAuthorities();
			}
			
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user_id, "samluser", authorities);
			token.setDetails(user);
									
			return token;
		} catch(UsernameNotFoundException e) {
			throw new UsernameNotFoundException("login.user.notfound");
		} catch(BadCredentialsException e){
			throw new BadCredentialsException(e.getMessage());
		} catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	public String getClientIp(HttpServletRequest request){
		String ip = request.getHeader("X-FORWARDED_FOR"); 
		
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)){
	        ip = request.getHeader("REMOTE_ADDR");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
		    ip = request.getHeader("Proxy-Client-IP"); 
		} 
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
		    ip = request.getHeader("WL-Proxy-Client-IP"); 
		} 
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
		    ip = request.getHeader("HTTP_CLIENT_IP"); 
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
		    ip = request.getRemoteAddr(); 
		}
		
		if(ip != null && ip.indexOf(",") > -1){
			ip = ip.substring(0, ip.indexOf(",")).trim();
		}
		return ip;
	}

	// 페스워드 찾기 - 이메일 검증
	public int chk_email(SVMUserVO vo) throws SiccException {
		SVMUserDAO mapper = sqlSession.getMapper(SVMUserDAO.class);
		try{		
			int result = 0;
			result = mapper.chk_email(vo.getTenant_id(), vo.getCp_cd(), vo.getEmail_id());
			return result;
		} catch(DataAccessException e) {
			throw SiccMessageUtil.getError(e);
		} catch(ClassCastException e) {
			throw SiccMessageUtil.getError(e);
		}
	}
	
	// Oauth2 Token 발급 받기 
	public String getOAuth2Token(String emailId, String password) {		
		
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		HttpSession session = request.getSession();
		
		final String GRANT_TYPE = "client_credentials";		
		
		String clientCredentials = CLIENT_ID + ":" + CLIENT_SECRET;
		String base64ClientCredentials = new String(Base64.encodeBase64(clientCredentials.getBytes()));
		
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.set("Accept", "application/json");
		headers.add("Authorization", "Basic " + base64ClientCredentials);		
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("username", emailId);
		params.add("password", password);
		params.add("grant_type", GRANT_TYPE); // 요청타입
		//params.add("system", SICC_SYSTEM);  // 시스템명칭
		
		//		String code = "";
		//		if(GRANT_TYPE.equals("authorization_code")) {  // client_credentails 
		//			params.add("code", code);
		//		} else if(GRANT_TYPE.equals("refresh_token")) {  // 토큰 재발급 
		//			params.add("refresh_token", code);
		//		}
		
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
	
		URI url = URI.create(ACCESS_TOKEN_URI);			
		String result = "";
		try {
			//ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
			//String result =  responseEntity.getBody();		
			ResponseEntity<Map> response = restTemplate.postForEntity(url, requestEntity, Map.class);			
			if(response.getStatusCode().value() == 200) {
				result = (String)response.getBody().get("access_token");
				session.setAttribute("oauth2AccessToken", result);
			}				
		} catch (HttpStatusCodeException exception) {
			int statusCode = exception.getStatusCode().value();
			System.out.println("HttpStatusCodeException :: "+ statusCode);
		}    
		
		if(result.isEmpty()) { 
	        if (session != null) {
	        	session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	        }			
		}
		
		return result;
	}	
	
}
