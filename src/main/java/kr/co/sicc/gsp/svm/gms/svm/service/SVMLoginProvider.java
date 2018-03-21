package kr.co.sicc.gsp.svm.gms.svm.service;

import java.util.Collection;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Component;

import kr.co.sicc.gsp.svm.gms.common.login.Role;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;


@Component
public class SVMLoginProvider implements AuthenticationProvider {
	
	private static final Logger logger = LoggerFactory.getLogger(SVMLoginProvider.class);
	
	@Autowired
	@Resource(name="svmSiccUserService")
	private SVMSiccUserService svmSiccUserService;
	
	//@Resource(name="SICC_SSO")
	@Value("${settings.SICC_SSO}")
	private Boolean SICC_SSO;
	
	public SVMLoginProvider(){
	}
	
	// for 2018 SaaS
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			String email = authentication.getName();
			String password = (String) authentication.getCredentials();
			SVMUserVO user;
			Collection<? extends Role> authorities = null;
			
			// for 2018 SaaS
//			String accessToken = svmSiccUserService.getOAuth2Token(email, password);
//			
//			//oauth2AccessToken			
//			if(accessToken.isEmpty()){
//				throw new BadCredentialsException("sys.user.message.disabled_user"); // You do not have the right to access.
//			} 
			//-- for 2018 SaaS
			
			// jwt 토큰에 계정정보 등 암호화해서 전달 됨 
			// accessToken 발행시에 userinfo 정보 받을수 있다면 받아서 사용. 현재는 DB acessToken 생성 성공시 다시 DB재조회해서 userinfo정보 가져오게 처리함.			
			user = svmSiccUserService.loadUserByUsername(email);
			
			authorities = user.getAuthorities();
			
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(email, password, authorities);
			token.setDetails(user);
						
			return token;
		} catch(UsernameNotFoundException e) {
			logger.info(e.toString());
			throw new UsernameNotFoundException(e.getMessage());
		} catch(BadCredentialsException e){
			logger.info(e.toString());
			throw new BadCredentialsException(e.getMessage());
		} catch(Exception e) {
			logger.info(e.toString());
			throw new RuntimeException(e.getMessage());
		}
	}

	/*
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			String email = authentication.getName();
			String password = (String) authentication.getCredentials();
			SVMUserVO user;
			Collection<? extends Role> authorities = null;
		    
//			if("".equals(email.trim())){
//				throw new UsernameNotFoundException("login.user.notfound");
//			}else if("".equals(password)){
//				throw new UsernameNotFoundException("login.user.notfound");
//			}
			
			user = svmSiccUserService.loadUserByUsername(email);

			if(!SICC_SSO) {

//				if(user.getAuthorities().isEmpty())
//					throw new BadCredentialsException("login.access.denied");
				
				byte[] saltByte = Base64Utils.decodeFromString(user.getSalt());
				//byte[] saltByte = FileCoder.base64ToByte(user.getSalt());
				String saltStr = new String(saltByte);
				
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				String strNewPassword = email + password + saltStr;
				logger.info("FileCoder.ComputeHash :  "  + FileCoder.ComputeHash(email + password,saltStr ));
				
				byte[] bNewPassword = strNewPassword.getBytes("UTF-8");
				digest.update(bNewPassword);
				
				byte[] bOutput = digest.digest();
				
				String comPassword = Base64Utils.encodeToString(bOutput);
				
//				logger.info("username : " + email + " / password : " + password + " / hash password : " + comPassword+" / salt : "+saltStr);
//		        logger.info("username : " + user.getUsername() + " / password : " + user.getPassword());
				
				if(!comPassword.equals(user.getPassword())){
					throw new BadCredentialsException("svm.message.login_misspell");
				}
			}
			
			authorities = user.getAuthorities();
			
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(email, password, authorities);
			token.setDetails(user);
						
			return token;
		} catch(UsernameNotFoundException e) {
			logger.info(e.toString());
			throw new UsernameNotFoundException(e.getMessage());
		} catch(BadCredentialsException e){
			logger.info(e.toString());
			throw new BadCredentialsException(e.getMessage());
		} catch(Exception e) {
			logger.info(e.toString());
			throw new RuntimeException(e.getMessage());
		}
	}
	*/
	
	@Override
	public boolean supports(Class<?> authentication) {
		if(authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class)){
			return true;
		}
		return false;
	}	

}
