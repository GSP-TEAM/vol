package kr.co.sicc.gsp.svm.gms.svm.controller;

import java.util.Locale;

//import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import kr.co.sicc.gsp.svm.gms.common.utils.file.CmmFileManager;
import kr.co.sicc.gsp.svm.gms.svm.service.SVMVolService;
import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.common.SiccController;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;

@Controller
public class SVMMainController extends SiccController {
    
//	@Autowired
//	SiccUserService siccUserService;
	
	@Autowired
	SVMVolService svmVolService;
	
	@Autowired
	CmmFileManager fileUpDown;
	
	
	@RequestMapping(value="/{lang}/svm/main")
	public String main(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
			logger.info("main");
			session.removeAttribute("userInfo");
			return "/svm/common/index";
	}
	
	@RequestMapping(value="/{lang}/svm/common")
	public String apply(Locale locale, Model model, HttpServletRequest request, HttpSession session,RedirectAttributes redirectAttr, 
			@PathVariable String lang) throws SiccException{
		
		SVMUserVO svmUserVO = (SVMUserVO)session.getAttribute("userInfo");
		session.setAttribute("SVMUserVO", svmUserVO);
		if(svmUserVO != null){
			//if(!"Y".equals(svmUserVO.getEmail_auth_yn())) {
			if(!"Y".equals(svmUserVO.getEmail_id_auth_yn())) return "redirect:/mail/handlerEmail";
			if("Y".equals(svmUserVO.getChange_pwd_yn())){
				redirectAttr.addAttribute("email", svmUserVO.getEmail());
				redirectAttr.addFlashAttribute("msg",getMessage("svm.message.info.password_yn",null, locale));
				return "redirect:/"+lang+"/svm/chngPw";
			}			
			return "redirect:/"+lang+"/svm/application/basicInfo";			
		}
		else 
			return "redirect:/"+lang+"/svm/main";
		
	}
	
	@RequestMapping(value="/{lang}/svm/about")
	public String about(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
		session.removeAttribute("userInfo");
		return "/svm/common/about";
	}
	
	@RequestMapping(value="/{lang}/svm/procedure")
	public String procedure(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
		session.removeAttribute("userInfo");
		return "/svm/common/procedure";
	}
	
	@RequestMapping(value="/{lang}/svm/volunteer")
	public String volunteer(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
		session.removeAttribute("userInfo");
		return "/svm/common/volunteer";
	}

	@RequestMapping(value="/{lang}/svm/contact")
	public String contact(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
		session.removeAttribute("userInfo");
		return "/svm/common/contact";
	}
	
	@RequestMapping(value="/{lang}/svm/forgotPw")
	public String forgotPw(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
		session.removeAttribute("userInfo");
		return "/svm/common/forgotPw";
	}
	@RequestMapping(value="/{lang}/svm/chngPw")
	public String chngPw(Locale locale, Model model, HttpServletRequest request, HttpSession session,
			@RequestParam(value = "email", required = false) String email,
			@PathVariable String lang) throws SiccException{
		model.addAttribute("email", email);
		session.removeAttribute("userInfo");
		return "/svm/common/chngPw";
	}
	@RequestMapping(value="/{lang}/svm/forgotPwAfter")
	public String forgotPwAfter(Locale locale, Model model, HttpServletRequest request, HttpSession session, 
			@PathVariable String lang) throws SiccException{
		String email = "";
		email = request.getParameter("email");
		session.removeAttribute("userInfo");
		model.addAttribute("email",email);
		return "/svm/common/forgotPwAfter";
	}
	
}
