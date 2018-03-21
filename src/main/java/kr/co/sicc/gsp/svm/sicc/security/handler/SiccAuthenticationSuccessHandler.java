package kr.co.sicc.gsp.svm.sicc.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

public class SiccAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	
	private RequestCache requestCache = new HttpSessionRequestCache();
	
	private String targetUrlParameter;
	
	private String defaultUrl;
	
	private boolean useReferer;
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
	public SiccAuthenticationSuccessHandler(){
		targetUrlParameter = "";
		defaultUrl = "/login";
//		defaultUrl = "/ko/svm/commom";
		System.out.println("SiccAuthenticationSuccessHandler >> SiccAuthenticationSuccessHandler();");
		useReferer = false;
	}
	
	public String getTargetUrlParameter() {
		return targetUrlParameter;
	}

	public void setTargetUrlParameter(String targetUrlParameter) {
		this.targetUrlParameter = targetUrlParameter;
	}

	public String getDefaultUrl() {
		return defaultUrl;
	}

	public void setDefaultUrl(String defaultUrl) {
		this.defaultUrl = defaultUrl;
	}

	public boolean isUseReferer() {
		return useReferer;
	}

	public void setUseReferer(boolean useReferer) {
		this.useReferer = useReferer;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		//createNewCookie(request, response);
		clearAuthenticationAttributes(request);
		setSessionUserDetails(request, authentication.getDetails());
		
		int intRedirectStrategy = decideRedirectStrategy(request, response);
//		System.out.println("onAuthenticationSuccess :: " + intRedirectStrategy);
//		System.out.println("onAuthenticationSuccess :: " + request.getParameter("cp_cd").toString());
		switch(intRedirectStrategy){
		case 1:
			useTargetUrl(request, response);
			break;
		case 2:
			useSessionUrl(request, response);
			break;
		case 3:
			useRefererUrl(request, response);
			break;
		default:
			redirectStrategy.sendRedirect(request, response, defaultUrl);
			//request.getRequestDispatcher(defaultUrl).forward(request, response);
			//useDefaultUrl(request, response);
		}
	}
	
	private void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

	private void setSessionUserDetails(HttpServletRequest request, Object userDetails) {
		HttpSession session = request.getSession();		
        session.setAttribute("userInfo", userDetails);        
        session.setAttribute("cp_cd", request.getParameter("cp_cd")==null?"":request.getParameter("cp_cd"));
    }
	
//	private void createNewCookie(HttpServletRequest request, HttpServletResponse response) {
//		Cookie ck = new Cookie("JSESSIONID", request.getSession().getId());
//		ck.setPath(request.getContextPath());
//		response.addCookie(ck);
//	}
	
	private void useTargetUrl(HttpServletRequest request, HttpServletResponse response) throws IOException{
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		if(savedRequest != null){
			requestCache.removeRequest(request, response);
		}
		String targetUrl = request.getParameter(targetUrlParameter);
		redirectStrategy.sendRedirect(request, response, targetUrl);
	}
	
	private void useSessionUrl(HttpServletRequest request, HttpServletResponse response) throws IOException{
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		String targetUrl = savedRequest.getRedirectUrl();
		redirectStrategy.sendRedirect(request, response, targetUrl);
	}
	
	private void useRefererUrl(HttpServletRequest request, HttpServletResponse response) throws IOException{
//		HttpSession session = request.getSession();
		String targetUrl = "/";
//		String targetUrl = String.valueOf(session.getAttribute("prevPage"));
//		if("null".equals(targetUrl)){
//			targetUrl = "/";
//		}
		redirectStrategy.sendRedirect(request, response, targetUrl);
	}
	
	private void useDefaultUrl(HttpServletRequest request, HttpServletResponse response) throws IOException{
		redirectStrategy.sendRedirect(request, response, defaultUrl);
	}
	
	/**
	 * URL redirect
	 * 순서는 
	 * targetUrlParameter -> Session -> REFERER -> default
	 * @param request
	 * @param response
	 * @return   1 : targetUrlParameter URL
	 *            2 : Session URL
	 *            3 : referer URL
	 *            0 : default URL
	 */
	private int decideRedirectStrategy(HttpServletRequest request, HttpServletResponse response){
		int result = 0;
		
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		
		if(!"".equals(targetUrlParameter)){
			String targetUrl = request.getParameter(targetUrlParameter);
			if(StringUtils.hasText(targetUrl)){
				result = 1;
			}else{
				if(savedRequest != null){
//					result = 2;
				}else{
					String refererUrl = request.getHeader("REFERER");
					if(useReferer && StringUtils.hasText(refererUrl)){
						result = 3;
					}else{
						result = 0;
					}
				}
			}
			
			return result;
		}
// Session URL 사용안함.				
//		if(savedRequest != null){
//			result = 2;
//			return result;
//		}
		
		String refererUrl = request.getHeader("REFERER");
		if(useReferer && StringUtils.hasText(refererUrl)){
			result = 3;
		}else{
			result = 0;
		}
		
		return result;
	}
}

