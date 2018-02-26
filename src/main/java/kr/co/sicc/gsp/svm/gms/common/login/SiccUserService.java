package kr.co.sicc.gsp.svm.gms.common.login;

import java.security.MessageDigest;
import java.util.Collection;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import kr.co.sicc.gsp.svm.gms.common.interceptor.BasicInfo;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;

@Service
public class SiccUserService implements UserDetailsService{
		
	@Autowired
	@Resource(name="sqlSession")
	private SqlSession session;
	
	@Autowired
	//@Qualifier("SICC_SYSTEM")
	@Value("${settings.SICC_SYSTEM}")
	private String SICC_SYSTEM;

	// kimjw sso
	//@Resource(name="SICC_SSO")
	@Value("${settings.SICC_SSO}")
	private Boolean SICC_SSO;
	
	@Override
	public UserInfo loadUserByUsername(String username) throws UsernameNotFoundException {
		LoginDAO mapper = session.getMapper(LoginDAO.class);
		UserInfo user = mapper.userInfo(username, SICC_SYSTEM);
		
		if(user == null) {
			if(SICC_SSO) {
				user = new UserInfo();
				user.setUsername(username);
				user.setSso_msg("login.user.notfound");
				
				return user;
			} else {
				throw new UsernameNotFoundException("User not found: " + username);
			}
		}
		
//		if(user == null)
//            throw new UsernameNotFoundException("User not found: " + username);
		
		if(!user.isEnabled()){
			throw new BadCredentialsException("sys.user.message.disabled_user");
		}
		
		if(user.getLoginFailCnt() >= 10){
		
			String flag = mapper.calculateLoginFailResetCriterion(username, SICC_SYSTEM);
			if(flag != null && flag.equals("Y")){
				user.setCurrent_system_cd(SICC_SYSTEM);
				mapper.loginFailCountReset(user);
			}else{
				throw new BadCredentialsException("login.access.denied_failcnt");
			}
		}

		List<? extends Role> roles = mapper.authList(username, SICC_SYSTEM);
		user.setAuth(roles);
		
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		user.setUser_ip(getClientIp(request));
		user.setCurrent_system_cd(SICC_SYSTEM);
		
		return user;
	}

	public int loginSuccess(UserInfo userinfo) {
		LoginDAO mapper = session.getMapper(LoginDAO.class);
		int result = mapper.loginSuccess(userinfo);
		result = mapper.loginFailCountReset(userinfo);		
		
		return result;
	}

	public int loginFail(UserInfo userinfo) {
		
		System.out.println("loginFail... ");
		
		LoginDAO mapper = session.getMapper(LoginDAO.class);
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		userinfo.setUser_ip(getClientIp(request));
		userinfo.setCurrent_system_cd(SICC_SYSTEM);		
		
		// for 2018 SaaS
		HttpSession session = request.getSession();
		BasicInfo bInfo = (BasicInfo)session.getAttribute("BasicInfo");
		userinfo.setTenant_id(bInfo.getTenant_id());
		userinfo.setCp_cd(bInfo.getCp_cd());
		//-- for 2018 SaaS
		
		//int result = mapper.loginFail(userinfo);
		//result = mapper.loginFailCount(userinfo);
		int result = 0;
		
		return result;
	}

	public int logout(UserInfo userinfo) {
		LoginDAO mapper = session.getMapper(LoginDAO.class);
		int result = mapper.logout(userinfo);
		
		return result;
	}
	// kimjw sso
	public UserInfo getUserInfo(String username) {
		LoginDAO mapper = session.getMapper(LoginDAO.class);
		UserInfo user = mapper.userInfo(username, SICC_SYSTEM);
		
		if(user != null) {
//			HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
//			user.setUser_ip(getClientIp(request));
			user.setCurrent_system_cd(SICC_SYSTEM);
		}
		
		return user;
	}

	// kimjw sso
	public Authentication authenticate_acs(UserInfo samluser) throws AuthenticationException {

		try {
			String user_id = samluser.getUsername();		
			UserInfo user;
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
	
	public boolean chkOldPassword(String struser_id, String strold_password) throws SiccException {
		try {
			LoginDAO mapper = session.getMapper(LoginDAO.class);
			
			UserInfo user = mapper.userInfo(struser_id, SICC_SYSTEM);
			
	
			byte[] saltByte = Base64Utils.decodeFromString(user.getSalt());
			String saltStr = new String(saltByte);
	
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			String strNewPassword = struser_id + strold_password + saltStr;
			
			byte[] bNewPassword = strNewPassword.getBytes("UTF-8");
			digest.update(bNewPassword);
			
			byte[] bOutput = digest.digest();
			
			String comPassword = Base64Utils.encodeToString(bOutput);
			
	        if(comPassword.equals(user.getPassword()))
				return true;
			else 
				return false;
		} catch(UsernameNotFoundException e) {
			throw new UsernameNotFoundException("login.user.notfound");
		} catch(BadCredentialsException e){
			throw new BadCredentialsException(e.getMessage());
		} catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	
}
