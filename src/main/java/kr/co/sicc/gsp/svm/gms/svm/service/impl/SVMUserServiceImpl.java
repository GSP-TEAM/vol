package kr.co.sicc.gsp.svm.gms.svm.service.impl;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Resource;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Base64Utils;

import kr.co.sicc.gsp.svm.gms.svm.dao.SVMUserDAO;
import kr.co.sicc.gsp.svm.gms.svm.service.SVMSiccUserService;
import kr.co.sicc.gsp.svm.gms.svm.service.SVMUserService;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.aeschiper.FileCoder;
import kr.co.sicc.gsp.svm.sicc.common.SiccMessageUtil;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;
import kr.co.sicc.gsp.svm.sicc.util.SVMSiccUserUtil;

@Service
public class SVMUserServiceImpl implements SVMUserService {

	@Autowired
	@Resource(name="sqlSession")
	SqlSession session;
	
	@Autowired
	@Resource(name="svmSiccUserService")
	private SVMSiccUserService svmSiccUserService;
	
	@Override
	@Transactional
	public void insert(SVMUserVO vo) throws SiccException {
		try {
			SVMUserDAO mapper = session.getMapper(SVMUserDAO.class);

			SVMSiccUserUtil.setDefaultUserInfo(vo);
			
			String strSalt = FileCoder.getSalt();
			String encPassword = FileCoder.ComputeHash(vo.getEmail_id() + vo.getPassword(), strSalt);
			String encSalt = FileCoder.byteToBase64(strSalt.getBytes("UTF-8"));
			vo.setPassword(encPassword);
			//vo.setEnc_salt(encSalt);
			vo.setSaltBase64(encSalt);
/*			
			// password	: 암호화하기 위한 salt값 생성
			String strSalt = FileCoder.getSalt();
			// user_id + password 와 salt 값을 조합하여 암호화된 암호를 생성한다.
			String newPassword = FileCoder.ComputeHash(vo.getEmail() + vo.getPassword(), strSalt);	
			// salt 값을 보호하기 위해 암호화하여 DB에 저장
			String saltBase64 = FileCoder.byteToBase64(strSalt.getBytes("UTF-8"));
			
			vo.setNewPassword(newPassword);
			vo.setSaltBase64(saltBase64);
*/			
//			// 그룹ID 값(배열 TO 문자열) 설정
//			STRING ASSIGNED_GROUP_ID = GMSSTRINGUTIL.TOTOKENFROMSTRING(VO.GETGRANTED_GROUP_ID(), ",");
//			VO.SETASSIGN_GROUP_ID(ASSIGNED_GROUP_ID);

			mapper.insert(vo);
			
		} catch(DataAccessException e) {
			throw SiccMessageUtil.getError(e);
		} catch(ClassCastException e) {
			throw SiccMessageUtil.getError(e);
		} catch(NoSuchAlgorithmException e) {
			throw SiccMessageUtil.getError(e);
		} catch(UnsupportedEncodingException e) {
			throw SiccMessageUtil.getError(e);
		} catch(Exception e){
			throw SiccMessageUtil.getError(e);
		}
	}

	@Override
	@Transactional
	public void insert_priv(SVMUserVO vo) throws SiccException {
		try {
			SVMUserDAO mapper = session.getMapper(SVMUserDAO.class);
			
			SVMSiccUserUtil.setDefaultUserInfo(vo);
			
			String[] system_priv_auth;
			String pre_system_cd = "";
			String system_cd 	= "";
			String pre_priv 	= "";
			String priv 		= "";
			StringBuffer auth 	= new StringBuffer();
			
			for(int i=0; i<vo.getChk_group_authority().length; i++) {
				system_priv_auth = vo.getChk_group_authority()[i].split("/");		// ex) "MED/MED_ADMIN/1", "MED/MED_ADMIN/2", "ADM/ADM_USER/2"
				system_cd 	= system_priv_auth[0];
				priv 		= system_priv_auth[1];
				
				if(!priv.equals(pre_priv) && i != 0) {
					vo.setPriv_system_cd(pre_system_cd);
					vo.setAccess_priv(pre_priv);
					vo.setAuthority(auth.toString());
					
					if(!vo.getAuthority().equals("") && !vo.getAuthority().equals("0")) {
						// SVMUSERPOWERD
						mapper.insert_auth(vo);
					}
					
					auth.setLength(0);
					auth.append(system_priv_auth[2]);
					
					pre_system_cd = system_cd;
					pre_priv = priv;
					
				}
//				else {
//					if(i == 0) {
//						pre_system_cd = system_cd;
//						pre_priv = priv;
//					}
//					auth.append(system_priv_auth[2]);
//				}
//				
//				// Last 
//				if(i == vo.getChk_group_authority().length-1) {
//					vo.setPriv_system_cd(system_cd);
//					vo.setAccess_priv(priv);
//					vo.setAuthority(auth.toString());
//					
//					if(!vo.getAuthority().equals("") && !vo.getAuthority().equals("0")) {
//						// SYSUSERPOWERD
//						mapper.insert_auth(vo);
//					}
//				}
			}
			
			// History
			vo.setStatus("UPDATE");
			vo.setRevision_history("Priv Insert : ");
//			mapper.insert_history(vo);
			
		} catch(DataAccessException e) {
			throw SiccMessageUtil.getError(e);
		} catch(ClassCastException e) {
			throw SiccMessageUtil.getError(e);
		} catch(Exception e){
			throw SiccMessageUtil.getError(e);
		}
	}

	@Override
	public void update(SVMUserVO vo) throws SiccException {
		System.out.println("SVMUserServiceImpl update");
		
	}

	@Override
	public void update_priv(SVMUserVO vo) throws SiccException {
		System.out.println("SVMUserServiceImpl update_priv");
		
	}


	// 페스워드 찾기 - 이메일 검증
	@Override
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
		} catch(Exception e){
			throw SiccMessageUtil.getError(e);
		}
	}

	@Override
	public void update_passwd(SVMUserVO vo) throws SiccException {
		
		try{
			SVMUserDAO mapper = session.getMapper(SVMUserDAO.class);

			SVMSiccUserUtil.setDefaultUserInfo(vo);
			
			// password	: 암호화하기 위한 salt값 생성
			String strSalt = FileCoder.getSalt();
			// user_id + password 와 salt 값을 조합하여 암호화된 암호를 생성한다.
			String newPassword = FileCoder.ComputeHash(vo.getEmail() + vo.getPassword(), strSalt);	
			// salt 값을 보호하기 위해 암호화하여 DB에 저장
			String saltBase64 = FileCoder.byteToBase64(strSalt.getBytes("UTF-8"));
			
			SVMUserVO userVo = new SVMUserVO();
			userVo.setEmail(vo.getEmail());
			userVo.setNewPassword(newPassword);
			userVo.setSaltBase64(saltBase64);
			userVo.setChange_pwd_yn(vo.getChange_pwd_yn());
			
			mapper.update(userVo);
		} catch(DataAccessException e) {
			throw SiccMessageUtil.getError(e);
		} catch(ClassCastException e) {
			throw SiccMessageUtil.getError(e);
		} catch(NoSuchAlgorithmException e) {
			throw SiccMessageUtil.getError(e);
		} catch(UnsupportedEncodingException e) {
			throw SiccMessageUtil.getError(e);
		} catch(Exception e){
			throw SiccMessageUtil.getError(e);
		}
		
		
	}

	@Override
	public boolean chk_passwd(SVMUserVO vo) throws SiccException {
		
		try {
			String email = vo.getEmail();
			String password = vo.getOld_password();
			
		    
			vo = svmSiccUserService.loadUserByUsername(email);
			byte[] saltByte = Base64Utils.decodeFromString(vo.getSalt());
			//byte[] saltByte = FileCoder.base64ToByte(user.getSalt());
			String saltStr = new String(saltByte);
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			String strNewPassword = email + password + saltStr;
			//logger.info("FileCoder.ComputeHash :  "  + FileCoder.ComputeHash(email + password,saltStr ));
			
			byte[] bNewPassword = strNewPassword.getBytes("UTF-8");
			digest.update(bNewPassword);
			
			byte[] bOutput = digest.digest();
			
			String comPassword = Base64Utils.encodeToString(bOutput);
			
			//logger.info("username : " + email + " / password : " + password + " / hash password : " + comPassword+" / salt : "+saltStr);
	        //logger.info("username : " + user.getUsername() + " / password : " + user.getPassword());
			
			if(!comPassword.equals(vo.getPassword())){
				return false;
			}else {
				return true;
			}
						
		} catch(UsernameNotFoundException e) {
			//logger.info(e.toString());
			throw new UsernameNotFoundException("login.user.notfound");
		} catch(BadCredentialsException e){
			//logger.info(e.toString());
			throw new BadCredentialsException(e.getMessage());
		} catch(Exception e) {
			//logger.info(e.toString());
			throw new RuntimeException(e.getMessage());
		}
	}

	// 페스워드 찾기 - 이메일 검증
	@Override
	public String chk_email_auth(String email) throws SiccException {
		SVMUserDAO mapper = session.getMapper(SVMUserDAO.class);
		try{		
			String result = "";
			result = mapper.chk_email_auth(email);
			return result;
		} catch(DataAccessException e) {
			throw SiccMessageUtil.getError(e);
		} catch(ClassCastException e) {
			throw SiccMessageUtil.getError(e);
		} catch(Exception e){
			throw SiccMessageUtil.getError(e);
		}
	}
}
