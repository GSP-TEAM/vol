package kr.co.sicc.gsp.svm.gms.svm.controller;

import java.util.Locale;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import kr.co.sicc.gsp.svm.gms.common.interceptor.BasicInfo;
import kr.co.sicc.gsp.svm.gms.common.login.SiccUserService;
import kr.co.sicc.gsp.svm.gms.svm.service.SVMUserService;
import kr.co.sicc.gsp.svm.gms.svm.service.SendMailService;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.common.SiccController;
import kr.co.sicc.gsp.svm.sicc.common.SiccMessageUtil;
import kr.co.sicc.gsp.svm.sicc.constants.MessageConstants;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;
import kr.co.sicc.gsp.svm.sicc.util.SiccBeanUtils;

@Controller
public class SVMUserController extends SiccController {

	@Autowired
	SVMUserService svmUserService;

	@Autowired
	SendMailService sendMailService;
	
	@Autowired
	MessageSource messageSource;
	
	@Autowired
	@Resource(name="siccUserService")
	private SiccUserService siccUserService;
	
	public SVMUserController(){
	}
	
	@RequestMapping(value="/{lang}/svm/user/{cmd}")
	public String users(
			Locale locale, Model model,
			@PathVariable String lang,
			@PathVariable String cmd,
			@ModelAttribute("SVMUserVO") SVMUserVO vo,
			HttpServletRequest request,
			RedirectAttributes redirectAttributes,
			HttpSession session//추가
			) throws SiccException{
		SVMUserVO userVo = new SVMUserVO();
		BasicInfo bInfo = (BasicInfo)session.getAttribute("BasicInfo");//추가
		try{
			SiccBeanUtils.copyProperties(userVo, vo, model);
			userVo.setTenant_id(bInfo.getTenant_id());
			userVo.setCp_cd(bInfo.getCp_cd());
			
			if(request != null ) {
				userVo.setUser_ip(siccUserService.getClientIp(request));
			}
			
			switch(cmd){
				case "list" :
					userVo.setForwardUrl("/svm/user/list");
//					userVo = svmUserService.list(userVo);
					logger.debug("SVMUserController >>  users > CASE list");
					model.addAttribute("svmUserVO", userVo);
					model.addAttribute("pageSet", userVo.getPageVo());
					break;
				case "input" :
					userVo.setForwardUrl("/svm/user/edit");
//					userVo = svmUserService.input(userVo);
					logger.debug("SVMUserController >>  users > CASE input");
					model.addAttribute("svmUserVO", userVo);
					break;
				case "edit":
					userVo.setForwardUrl("/svm/user/edit");
//					userVo = svmUserService.edit(userVo);
					logger.debug("SVMUserController >>  users > CASE edit");
					model.addAttribute("svmUserVO", userVo);
					break;
				case "insert" :
					logger.debug("SVMUserController >>  users > CASE insert");
					logger.debug("userVO >>> "+userVo.toString());
					logger.debug("userVO >>> "+userVo.getEmail());
					if( 0 < svmUserService.chk_email(userVo)){
						if("N".equals(svmUserService.chk_email_auth(userVo.getEmail()))){
							SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.info.msg.duplicate_email_and_no_auth",null, locale), MessageConstants.SHOW_TYPE_POPUP);
						}else{
							SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.info.msg.duplicate_email",null, locale), MessageConstants.SHOW_TYPE_POPUP);
						}
						userVo.setRedirectUrl("/svm/application/application", lang);
					}else if("".equals(userVo.getEmail_id().trim())){
						SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.message.mandatory_email",null, locale), MessageConstants.SHOW_TYPE_POPUP);
						userVo.setRedirectUrl("/svm/application/application", lang);
					}else if("".equals(userVo.getPassword().trim())){
						SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("sys.user.message.input_password",null, locale), MessageConstants.SHOW_TYPE_POPUP);
						userVo.setRedirectUrl("/svm/application/application", lang);
					}else if("".equals(userVo.getPassword_confirm().trim())){
						SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.message.input_confirm_password",null, locale), MessageConstants.SHOW_TYPE_POPUP);
						userVo.setRedirectUrl("/svm/application/application", lang);
					}else if("".equals(userVo.getBirth_date().trim())){
						SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.message.no_input_birth",null, locale), MessageConstants.SHOW_TYPE_POPUP);
						userVo.setRedirectUrl("/svm/application/application", lang);
					} else {
						userVo.setEmail_id_auth_yn("Y");
						userVo.setSubmit_yn("N");
						userVo.setPassword_chg_yn("N");
						userVo.setUse_yn("Y");
						userVo.setAssign_group_id("SVM_USER");
						
						//email 인증 Y로 설정
						userVo.setEmail_id_auth_yn("Y");
						svmUserService.insert(userVo);
						
						//mail인증 사용 x - auth_yn 값을 Y로 고정하고 forwarding
						userVo.setForwardUrl("/common/mail/recieveEmail");
						model.addAttribute("authYn", userVo.getEmail_id_auth_yn());
						model.addAttribute("email", userVo.getEmail_id());
						///////////////////
						//SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.info.msg.send_auth_mail",null, locale), MessageConstants.SHOW_TYPE_POPUP);
					}
					redirectAttributes.addFlashAttribute("svmUserVo", userVo);
					redirectAttributes.addFlashAttribute("isRegistered",true);
					break;
				case "update" :
					userVo.setRedirectUrl("/svm/user/edit", lang);
					svmUserService.update(userVo);
					logger.debug("SVMUserController >>  users > CASE update");
					SiccMessageUtil.saveSuccess(redirectAttributes, "Update Success", MessageConstants.SHOW_TYPE_POPUP);
					redirectAttributes.addFlashAttribute("svmUserVO", userVo);
					break;
				case "delete" :
					userVo.setRedirectUrl("/svm/user/list", lang);
					logger.debug("SVMUserController >>  users > CASE delete");
//					int cnt = svmUserService.delete(userVo);
//					SiccMessageUtil.saveSuccess(redirectAttributes, getMessage("success.message.delete", locale, cnt), MessageConstants.SHOW_TYPE_POPUP);
					redirectAttributes.addFlashAttribute("svmUserVO", userVo);
					break;
				default:
					break;
			}
		}catch(SiccException e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, getMessage(e.getCode(), locale), MessageConstants.SHOW_TYPE_POPUP);
			return userVo.getErrorUrl();
		}catch(Exception e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, "Exception", MessageConstants.SHOW_TYPE_POPUP);
			return userVo.getErrorUrl();
		}
		
		return userVo.getUrl();
	}
	
	@RequestMapping(value="/{lang}/user/resendEmail")
	public String resendEmail(
			Locale locale, Model model,
			@PathVariable String lang,
			@ModelAttribute("svmUserVo") SVMUserVO vo,
			HttpSession session,
			RedirectAttributes redirectAttributes
			) throws SiccException{
		SVMUserVO userVo = new SVMUserVO();
		try{	
				SiccBeanUtils.copyProperties(userVo, vo, model);
				SVMUserVO userInfo = (SVMUserVO) session.getAttribute("userInfo");
				//회원가입 후 바로 RESEND MAIL 클릭 예외
				if(userInfo == null ){
					redirectAttributes.addAttribute("svmUserVo", vo);
					userVo.setRedirectUrl("mail/resendEmail","");
				}else{
					userVo.setRedirectUrl("login","");
					if(userInfo.getEmail() != null){
						sendMailService.sendAuthEmail(userInfo.getEmail(),vo.getUser_ip());
					}
				}
				SiccMessageUtil.saveSuccess(redirectAttributes, messageSource.getMessage("svm.info.msg.send_auth_mail",null, locale), MessageConstants.SHOW_TYPE_POPUP);
				redirectAttributes.addFlashAttribute("userInfo", userInfo);
				redirectAttributes.addFlashAttribute("resend",true);
		}catch(SiccException e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, getMessage(e.getCode(), locale), MessageConstants.SHOW_TYPE_POPUP);
			return userVo.getErrorUrl();
		}catch(Exception e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, "Exception", MessageConstants.SHOW_TYPE_POPUP);
			return userVo.getErrorUrl();
		}
		
		return userVo.getUrl();
	}
	
	@RequestMapping(value="/{lang}/svm/user/data/{cmd}", method=RequestMethod.POST)
	@ResponseBody
	public SVMUserVO listData(
			Locale locale, Model model,
			@PathVariable String lang,
			@PathVariable String cmd,
			@ModelAttribute("SVMUserVO") SVMUserVO vo
			) throws SiccException{
		
		SVMUserVO userVo = new SVMUserVO();
		try{
			SiccBeanUtils.copyProperties(userVo, vo, model);
			
			switch(cmd){
				case "listData" :
//					userVo = svmUserService.list(userVo);
					logger.debug("case >>>  listData");
					break;
				case "delete" :
//					int cnt = svmUserService.delete(userVo);
//					SiccMessageUtil.saveSuccess(userVo, getMessage("success.message.delete", locale, cnt), MessageConstants.SHOW_TYPE_POPUP);
					logger.debug("case >>>  delete");
					break;
				default:
					break;
			}
			return userVo;
		}catch(SiccException e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, getMessage(e.getCode(), locale), MessageConstants.SHOW_TYPE_POPUP);
			return userVo;
		}catch(Exception e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, "Exception", MessageConstants.SHOW_TYPE_POPUP);
			return userVo;
		}
	}
	@RequestMapping(value="/svm/user/chngPw")
	@ResponseBody
	public SVMUserVO chngPw(
			Locale locale, 
			Model model, 
			HttpSession session,
			HttpServletRequest request,
			@ModelAttribute("userVo") SVMUserVO vo
			) throws SiccException{
		
		try{
			// 세션정보에 파라미터 정보 저장
			//SVMUserVO user = (SVMUserVO) session.getAttribute("userInfo");
			vo.setUser_ip(siccUserService.getClientIp(request));
			vo.setOld_password(vo.getOld_password());
			vo.setPassword(vo.getPassword());
			vo.setPassword_confirm(vo.getPassword_confirm());
			vo.setEmail(vo.getEmail());
			vo.setChange_pwd_yn("N");
			
			if("N".equals(svmUserService.chk_email_auth(vo.getEmail()))){
				// email 인증 확인
				vo.setSuccess(false);
				vo.setMsg("EA");
			}
			else if(0 == svmUserService.chk_email(vo)){
				// email 확인
				vo.setSuccess(false);
				vo.setMsg("EM");
			}	// 기존 패스워드 확인
			else if(svmUserService.chk_passwd(vo)){
				// 패스 워드 변경
				svmUserService.update_passwd(vo);
			}else {
				vo.setSuccess(false);
				vo.setMsg("PWD");
			}
			return vo;
		}catch(SiccException e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(vo, getMessage(e.getCode(), locale), MessageConstants.SHOW_TYPE_POPUP);
			return vo;
		}catch(Exception e){
			logger.debug("SiccException", e);
			SiccMessageUtil.saveError(model, "Exception", MessageConstants.SHOW_TYPE_POPUP);
			return vo;
		}
	}
	
}
