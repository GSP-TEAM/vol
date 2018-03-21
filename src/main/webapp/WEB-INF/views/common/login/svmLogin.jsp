<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ include file="/WEB-INF/views/common/include/common.jsp"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<!DOCTYPE html>

<% 
String htmlLang = "";
if( "in".equalsIgnoreCase(lang) ){
	htmlLang = "id";
}else{
	htmlLang = lang;
}
%>
<html lang="<%= htmlLang  %>">
<head>
<!-- <meta http-equiv="X-UA-Compatible" content="IE=edge" /> -->
<!-- <meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> -->
<!-- <meta name="Keywords" content="" /> -->
<!-- <meta name="Description" content="" /> -->
<!-- <meta http-equiv="Cache-Control" content="no-cache" />  -->
<!-- <meta http-equiv="Expires" content="0" />  -->
<!-- <meta http-equiv="Pragma" content="no-cache" /> -->
<!-- <meta name="viewport" content="user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, width=device-width" /> -->

<form id="loginForm" name="loginForm" method="post" autocomplete="off" action="loginProcess">
	<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
	<input type="hidden" name="loginRedirect" value="${loginRedirect}" />
	<input type="hidden" name="lang" value="${lang}" />


	<div class="contents_wrap_01 contents_support_01">
		<div class="contents_top">
			<div class="con_title"><spring:message code="svm.title.application"/></div>
			<ul class="con_location">
				<li><spring:message code="svm.title.home"/></li>
				<li><spring:message code="svm.title.application"/></li>
			</ul>
		</div>

<div class="contents">
<!-- ▼contents▼ -->
<div class="tab_01">
	<ul>
		<li class="" id="tab_register" onclick="goMenu('svm/application/application')"><em><spring:message code="svm.tab.RegisterApplication"/></em></li>
		<li class="on" id="tab_modify"><em><spring:message code="svm.tab.ModifyApplication"/></em></li>
	</ul>
</div>
			
<!--▼ form_register table_write-->
<div class="tab_01_contents ">

<div class="table_write table_write_support_01 table_write_support_01_add" style="margin-top:30px;">
	<div>
			<dl>
				<dt class="cell_01" >
					<strong><spring:message code="svm.header.email"/></strong>
				</dt>
				<dd class="">
					<strong>
						<input type="text" id="id" name="id" class="input_01" style="width:577px;" value="" maxlength="60" placeholder="ex) aaa@gmail.com"/>
					</strong>
				</dd>
			</dl>
		</div>
	
		<div>
			<dl>
				<dt class="cell_01" >
					<strong><spring:message code="svm.header.password"/></strong>
				</dt>
				<dd class="">
					<strong>
						<input type="password" id="pw" name="pw" class="input_01" style=" width:577px;" value="" placeholder="Password" onkeyup="enterkey();">
						<div class="login_form">
						<div class="error_wrap" id="errorMsg">
							<c:if test="${securityExceptionMsg ne null }">			
								<span class="error_01" style="display:block;" >
									<i class="icon-care"></i><span style="color: #f2394a;">${securityExceptionMsg}</span>
								</span>
			 				</c:if>
						</div>
						<div class="add_btn_01">
							<a href="#link" onclick="goMenu('svm/chngPw');"><spring:message code="svm.button.want_change_password"/></a>
							<a href="#link" onclick="goMenu('svm/forgotPw');"><spring:message code="svm.button.forgotten_password"/></a>
						</div>
					</strong>
				</dd>
			</dl>
		</div>
	</div>
	<ul class="error_wrap" style="display:block;">
		<li><spring:message code="svm.info.forgot_msg"/> </li>
	</ul>
	
	
	<div class="btn_area_01 btn_support_01 btn_support_01_add" style="margin:30px 0 10px 0;">
		<div class="btn_center">
			<a href="#void" class="btn_02" onclick="login();" ><spring:message code="svm.button.login"/></a>
		</div>
	</div>



<!-- ▲contents▲ -->
</div>
</div>
</form>


<script type="text/javascript">
//<![CDATA[
    $(document).ready(function(){
    	if('${securityExceptionMsg}' != ''){
    		setTimeout(function(){ 
	    		$("#errorMsg").remove();
			}, 8500);
    	}
    	
    	var lang = $('#lang').val();
    	
    	if(undefined == lang || '' == lang){
    		lang = '<%=lang%>';
    	}
   		$('#sel_lang option[value='+lang+']').prop('selected', true);
    	
    	$('#sel_lang').change(function(){
    		changeLang($(this).val());
    	});
    	
    	var menuUrl = location.pathname.split('/svm/').pop();
    	var seq = -1;
    	switch(menuUrl){
    		case "common" 	 : seq = 0; break;			
    		case "about" 	 : seq = 1; break;			
    		case "procedure" : seq = 2; break;			
    		case "volunteer" : seq = 3; break;			
    		case "contact" 	 : seq = 4; break;			
    	}
    	console.log(menuUrl);
    	console.log(seq);
    	$(".top_support_menu li.on").removeClass('on');
    	if(seq != -1) $(".top_support_menu li").eq(seq).addClass('on');
    });

    function changeLang(lang){
		var frm = document.loginForm;
		frm.lang.value = lang;
		
		frm.action = '/changeLocale';
		frm.submit();
	}
    
    function login(){    	
//     	alert("login");
    	document.getElementById('loginForm').submit();
    }
    
    function enterkey() {
        if (window.event.keyCode == 13) {
             login();
        }
	}

//]]>

//     (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
//     	  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
//     	  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
//     	  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
    	 
//     	  ga('create', 'UA-106617353-1', 'auto');
//     	  ga('send', 'pageview');


</script>