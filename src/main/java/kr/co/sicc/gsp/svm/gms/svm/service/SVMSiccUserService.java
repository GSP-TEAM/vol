package kr.co.sicc.gsp.svm.gms.svm.service;

import java.util.Collection;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import kr.co.sicc.gsp.svm.gms.common.interceptor.BasicInfo;
import kr.co.sicc.gsp.svm.gms.common.login.Role;
import kr.co.sicc.gsp.svm.gms.svm.dao.SVMLoginDAO;
import kr.co.sicc.gsp.svm.gms.svm.dao.SVMUserDAO;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.common.SiccMessageUtil;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;
import kr.co.sicc.gsp.svm.sicc.util.SiccBeanUtils;

@Service
public class SVMSiccUserService implements UserDetailsService{
		
	@Autowired
	@Resource(name="sqlSession")
	private SqlSession session;
	
//	@Autowired
//	@Qualifier("SICC_SYSTEM")
//	private String SICC_SYSTEM;

	//@Resource(name="SICC_SSO")
	@Value("${settings.SICC_SSO}")
	private Boolean SICC_SSO;
	
	@Override
	public SVMUserVO loadUserByUsername(String email) throws UsernameNotFoundException {
		SVMLoginDAO mapper = session.getMapper(SVMLoginDAO.class);
		
		// for 2018 SaaS
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
		//-- for 2018 SaaS
		
		
		///////////////////////////////////////		
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
		
		////////////////////////사용 가능하도록 강제 설정
		user.setEnabled(true);
		////////////////////
		
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

		//List<? extends Role> roles = mapper.authList(email); 수정
		List<? extends Role> roles = mapper.authList(tenantId, cpcd, email);
		user.setAuth(roles);
		
//		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		user.setUser_ip(getClientIp(request));
//		user.setCurrent_system_cd(SICC_SYSTEM);
		
		return user;
	}
	
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
		SVMLoginDAO mapper = session.getMapper(SVMLoginDAO.class);
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
		SVMUserDAO mapper = session.getMapper(SVMUserDAO.class);
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
	
	
}
