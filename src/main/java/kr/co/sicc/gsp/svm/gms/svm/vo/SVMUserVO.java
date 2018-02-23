package kr.co.sicc.gsp.svm.gms.svm.vo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import kr.co.sicc.gsp.svm.gms.common.login.Role;
import kr.co.sicc.gsp.svm.sicc.common.vo.SiccGenericVO;

@SuppressWarnings("serial")
public class SVMUserVO extends SiccGenericVO  implements UserDetails {
	
	private List<Map<String, Object>> list_priv = new ArrayList<Map<String, Object>>();
	private List<Map<String, Object>> list_auth = new ArrayList<Map<String, Object>>();
	private List<Map<String, Object>> list_granted_priv = new ArrayList<Map<String, Object>>();
	
	private String search_system_cd = "";
	private String search_use_yn = "";
	private String search_user_id = "";
	private String search_user_group = "";
	private String search_user_nm = "";
	private String search_order = "";
	private String search_group_system_cd = "";
	private String search_group_id = "";
	
	private String[] chk = null;
	private String[] hd_user_id = null;
	private String[] hd_user_nm = null;
	private String[] hd_system_cd = null;
	private String[] search_granted_group_id = null;
	private String[] granted_group_id = null;
	private String[] chk_granted_authority = null;
	private String[] chk_group_authority = null;
	
	private String p_user_id = "";
	private String p_system_cd = "";
	private String system_cd = "";
	private String user_id = "";
	//private String password = "";
	private String old_password = "";
	private String password_confirm = "";
	private String user_nm = "";
	private String dept_cd = "";
	private String venue_cd = "";
	private String work_area_cd = "";
	private String corps_cd = "";
	private String part_cd = "";
	//private String use_yn = "";
	private String change_pwd_yn = "";
	private String login_fail_cnt = "";
	private String user_group = "";
	private String group_id = "";
	private String user_idx1 = "";
	private String user_idx2 = "";
	private String user_idx3 = "";
	private String user_idx4 = "";
	private String user_idx5 = "";
	//private String assign_group_id = "";
	private String group_system_cd = "";
	private String priv_system_cd = "";
	private String authority = "";
	private String access_priv = "";
	private String pre_group_id = "";
	private String status = "";
	private String kind = "";
	private String revision_history = "";

	private String duplicate_check_yn = "";
	
	private String ad_no = "";
	private String email = "";
	
	private String email_dummy = "";
	private String email_auth_yn = "";
	private String birth_date = "";
	//private String submit_yn = "";
	private String save_tab_cd = "";
	
	// 암호화
	private String newPassword = "";
	private String saltBase64 = "";
	private String salt = "";
	
	private String sso_msg = "";
	
	//-------
	
	//추가되는 것들!!!!
	private String tenant_id;
	private String cp_cd;
	private String email_id;
	private String email_id_auth_yn;
	private String password;
	private String use_yn;
	private String email_id_auth_id;
	private String password_chg_yn;
	private String birth_dt;
	private String submit_yn;
	private Date submit_date;
	private String save_tab_id;
	private String assign_group_id;
	private Date crt_date;
	private String crt_id;
	private String crt_ip;
	private String enc_salt;
	private Date udt_date;
	private String udt_id;
	private String udt_ip;
	
	
	//////////////////////////
	
	private List<? extends Role> auth;
	private boolean accountNonExpired = true;
	private boolean accountNonLocked = true;
	private boolean credentialsNonExpired = true;
	private boolean enabled = true;
	
	@Override
	public Collection<? extends Role> getAuthorities() {
		// TODO Auto-generated method stub
		return this.auth;
	}

	public void setAuth(List<? extends Role> auth) {
		this.auth = auth;
	}



	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}



	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}



	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}



	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}



	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}



	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}



	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getAd_no() {
		return ad_no;
	}

	public void setAd_no(String ad_no) {
		this.ad_no = ad_no;
	}

	public List<? extends Role> getAuth() {
		return auth;
	}

	public String getSso_msg() {
		return sso_msg;
	}
	public void setSso_msg(String sso_msg) {
		this.sso_msg = sso_msg;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public String getKind() {
		return kind;
	}
	public void setKind(String kind) {
		this.kind = kind;
	}
	public String getDuplicate_check_yn() {
		return duplicate_check_yn;
	}
	public void setDuplicate_check_yn(String duplicate_check_yn) {
		this.duplicate_check_yn = duplicate_check_yn;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public List<Map<String, Object>> getList_priv() {
		return list_priv;
	}
	public void setList_priv(List<Map<String, Object>> list_priv) {
		this.list_priv = list_priv;
	}
	public List<Map<String, Object>> getList_auth() {
		return list_auth;
	}
	public void setList_auth(List<Map<String, Object>> list_auth) {
		this.list_auth = list_auth;
	}
	public List<Map<String, Object>> getList_granted_priv() {
		return list_granted_priv;
	}
	public void setList_granted_priv(List<Map<String, Object>> list_granted_priv) {
		this.list_granted_priv = list_granted_priv;
	}
	public String getSearch_system_cd() {
		return search_system_cd;
	}
	public void setSearch_system_cd(String search_system_cd) {
		this.search_system_cd = search_system_cd;
	}
	public String getSearch_use_yn() {
		return search_use_yn;
	}
	public void setSearch_use_yn(String search_use_yn) {
		this.search_use_yn = search_use_yn;
	}
	public String getSearch_user_id() {
		return search_user_id;
	}
	public void setSearch_user_id(String search_user_id) {
		this.search_user_id = search_user_id;
	}
	public String getSearch_user_group() {
		return search_user_group;
	}
	public void setSearch_user_group(String search_user_group) {
		this.search_user_group = search_user_group;
	}
	public String getSearch_user_nm() {
		return search_user_nm;
	}
	public void setSearch_user_nm(String search_user_nm) {
		this.search_user_nm = search_user_nm;
	}
	public String getSearch_order() {
		return search_order;
	}
	public void setSearch_order(String search_order) {
		this.search_order = search_order;
	}
	public String getSearch_group_system_cd() {
		return search_group_system_cd;
	}
	public void setSearch_group_system_cd(String search_group_system_cd) {
		this.search_group_system_cd = search_group_system_cd;
	}
	public String getSearch_group_id() {
		return search_group_id;
	}
	public void setSearch_group_id(String search_group_id) {
		this.search_group_id = search_group_id;
	}
	public String[] getChk() {
		return chk;
	}
	public void setChk(String[] chk) {
		if(chk == null){
			this.chk = new String[0];
		}else{
			this.chk = Arrays.copyOf(chk, chk.length);
		}
	}
	public String[] getHd_user_id() {
		return hd_user_id;
	}
	public void setHd_user_id(String[] hd_user_id) {
		if(hd_user_id == null){
			this.hd_user_id = new String[0];
		}else{
			this.hd_user_id = Arrays.copyOf(hd_user_id, hd_user_id.length);
		}
	}
	public String[] getHd_user_nm() {
		return hd_user_nm;
	}
	public void setHd_user_nm(String[] hd_user_nm) {
		if(hd_user_nm == null){
			this.hd_user_nm = new String[0];
		}else{
			this.hd_user_nm = Arrays.copyOf(hd_user_nm, hd_user_nm.length);
		}
	}
	public String[] getHd_system_cd() {
		return hd_system_cd;
	}
	public void setHd_system_cd(String[] hd_system_cd) {
		if(hd_system_cd == null){
			this.hd_system_cd = new String[0];
		}else{
			this.hd_system_cd = Arrays.copyOf(hd_system_cd, hd_system_cd.length);
		}
	}
	public String[] getSearch_granted_group_id() {
		return search_granted_group_id;
	}
	public void setSearch_granted_group_id(String[] search_granted_group_id) {
		if(search_granted_group_id == null){
			this.search_granted_group_id = new String[0];
		}else{
			this.search_granted_group_id = Arrays.copyOf(search_granted_group_id, search_granted_group_id.length);
		}
	}
	public String[] getGranted_group_id() {
		return granted_group_id;
	}
	public void setGranted_group_id(String[] granted_group_id) {
		if(granted_group_id == null){
			this.granted_group_id = new String[0];
		}else{
			this.granted_group_id = Arrays.copyOf(granted_group_id, granted_group_id.length);
		}
	}
	public String[] getChk_granted_authority() {
		return chk_granted_authority;
	}
	public void setChk_granted_authority(String[] chk_granted_authority) {
		if(chk_granted_authority == null){
			this.chk_granted_authority = new String[0];
		}else{
			this.chk_granted_authority = Arrays.copyOf(chk_granted_authority, chk_granted_authority.length);
		}
	}
	public String[] getChk_group_authority() {
		return chk_group_authority;
	}
	public void setChk_group_authority(String[] chk_group_authority) {
		if(chk_group_authority == null){
			this.chk_group_authority = new String[0];
		}else{
			this.chk_group_authority = Arrays.copyOf(chk_group_authority, chk_group_authority.length);
		}
	}
	public String getP_user_id() {
		return p_user_id;
	}
	public void setP_user_id(String p_user_id) {
		this.p_user_id = p_user_id;
	}
	public String getP_system_cd() {
		return p_system_cd;
	}
	public void setP_system_cd(String p_system_cd) {
		this.p_system_cd = p_system_cd;
	}
	public String getSystem_cd() {
		return system_cd;
	}
	public void setSystem_cd(String system_cd) {
		this.system_cd = system_cd;
	}
	public String getUser_id() {
		return user_id;
	}
	public void setUser_id(String user_id) {
		this.user_id = user_id;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getOld_password() {
		return old_password;
	}
	public void setOld_password(String old_password) {
		this.old_password = old_password;
	}
	public String getPassword_confirm() {
		return password_confirm;
	}
	public void setPassword_confirm(String password_confirm) {
		this.password_confirm = password_confirm;
	}
	public String getUser_nm() {
		return user_nm;
	}
	public void setUser_nm(String user_nm) {
		this.user_nm = user_nm;
	}
	public String getDept_cd() {
		return dept_cd;
	}
	public void setDept_cd(String dept_cd) {
		this.dept_cd = dept_cd;
	}
	public String getVenue_cd() {
		return venue_cd;
	}
	public void setVenue_cd(String venue_cd) {
		this.venue_cd = venue_cd;
	}
	public String getWork_area_cd() {
		return work_area_cd;
	}
	public void setWork_area_cd(String work_area_cd) {
		this.work_area_cd = work_area_cd;
	}
	public String getCorps_cd() {
		return corps_cd;
	}
	public void setCorps_cd(String corps_cd) {
		this.corps_cd = corps_cd;
	}
	public String getPart_cd() {
		return part_cd;
	}
	public void setPart_cd(String part_cd) {
		this.part_cd = part_cd;
	}
	public String getChange_pwd_yn() {
		return change_pwd_yn;
	}
	public void setChange_pwd_yn(String change_pwd_yn) {
		this.change_pwd_yn = change_pwd_yn;
	}
	public String getLogin_fail_cnt() {
		return login_fail_cnt;
	}
	public void setLogin_fail_cnt(String login_fail_cnt) {
		this.login_fail_cnt = login_fail_cnt;
	}
	public String getUser_group() {
		return user_group;
	}
	public void setUser_group(String user_group) {
		this.user_group = user_group;
	}
	public String getGroup_id() {
		return group_id;
	}
	public void setGroup_id(String group_id) {
		this.group_id = group_id;
	}
	public String getUser_idx1() {
		return user_idx1;
	}
	public void setUser_idx1(String user_idx1) {
		this.user_idx1 = user_idx1;
	}
	public String getUser_idx2() {
		return user_idx2;
	}
	public void setUser_idx2(String user_idx2) {
		this.user_idx2 = user_idx2;
	}
	public String getUser_idx3() {
		return user_idx3;
	}
	public void setUser_idx3(String user_idx3) {
		this.user_idx3 = user_idx3;
	}
	public String getUser_idx4() {
		return user_idx4;
	}
	public void setUser_idx4(String user_idx4) {
		this.user_idx4 = user_idx4;
	}
	public String getUser_idx5() {
		return user_idx5;
	}
	public void setUser_idx5(String user_idx5) {
		this.user_idx5 = user_idx5;
	}
	public String getAssign_group_id() {
		return assign_group_id;
	}
	public void setAssign_group_id(String assign_group_id) {
		this.assign_group_id = assign_group_id;
	}
	public String getGroup_system_cd() {
		return group_system_cd;
	}
	public void setGroup_system_cd(String group_system_cd) {
		this.group_system_cd = group_system_cd;
	}
	public String getPriv_system_cd() {
		return priv_system_cd;
	}
	public void setPriv_system_cd(String priv_system_cd) {
		this.priv_system_cd = priv_system_cd;
	}
	public String getAuthority() {
		return authority;
	}
	public void setAuthority(String authority) {
		this.authority = authority;
	}
	public String getAccess_priv() {
		return access_priv;
	}
	public void setAccess_priv(String access_priv) {
		this.access_priv = access_priv;
	}
	public String getPre_group_id() {
		return pre_group_id;
	}
	public void setPre_group_id(String pre_group_id) {
		this.pre_group_id = pre_group_id;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public String getRevision_history() {
		return revision_history;
	}
	public void setRevision_history(String revision_history) {
		this.revision_history = revision_history;
	}
	public String getEmail_dummy() {
		return email_dummy;
	}
	public void setEmail_dummy(String email_dummy) {
		this.email_dummy = email_dummy;
	}
	public String getEmail_auth_yn() {
		return email_auth_yn;
	}
	public void setEmail_auth_yn(String email_auth_yn) {
		this.email_auth_yn = email_auth_yn;
	}
	public String getBirth_date() {
		return birth_date;
	}
	public void setBirth_date(String birth_date) {
		this.birth_date = birth_date;
	}
	public String getSave_tab_cd() {
		return save_tab_cd;
	}
	public void setSave_tab_cd(String save_tab_cd) {
		this.save_tab_cd = save_tab_cd;
	}
	public String getNewPassword() {
		return newPassword;
	}
	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
	public String getSaltBase64() {
		return saltBase64;
	}
	public void setSaltBase64(String saltBase64) {
		this.saltBase64 = saltBase64;
	}

	public String getTenant_id() {
		return tenant_id;
	}

	public void setTenant_id(String tenant_id) {
		this.tenant_id = tenant_id;
	}

	public String getEmail_id() {
		return email_id;
	}

	public void setEmail_id(String email_id) {
		this.email_id = email_id;
	}

	public String getEmail_id_auth_yn() {
		return email_id_auth_yn;
	}

	public void setEmail_id_auth_yn(String email_id_auth_yn) {
		this.email_id_auth_yn = email_id_auth_yn;
	}

	public String getUse_yn() {
		return use_yn;
	}

	public void setUse_yn(String use_yn) {
		this.use_yn = use_yn;
	}

	public String getEmail_id_auth_id() {
		return email_id_auth_id;
	}

	public void setEmail_id_auth_id(String email_id_auth_id) {
		this.email_id_auth_id = email_id_auth_id;
	}

	public String getPassword_chg_yn() {
		return password_chg_yn;
	}

	public void setPassword_chg_yn(String password_chg_yn) {
		this.password_chg_yn = password_chg_yn;
	}

	public String getBirth_dt() {
		return birth_dt;
	}

	public void setBirth_dt(String birth_dt) {
		this.birth_dt = birth_dt;
	}

	public String getSubmit_yn() {
		return submit_yn;
	}

	public void setSubmit_yn(String submit_yn) {
		this.submit_yn = submit_yn;
	}

	public Date getSubmit_date() {
		return submit_date;
	}

	public void setSubmit_date(Date submit_date) {
		this.submit_date = submit_date;
	}

	public String getSave_tab_id() {
		return save_tab_id;
	}

	public void setSave_tab_id(String save_tab_id) {
		this.save_tab_id = save_tab_id;
	}

	public Date getCrt_date() {
		return crt_date;
	}

	public void setCrt_date(Date crt_date) {
		this.crt_date = crt_date;
	}

	public String getCrt_id() {
		return crt_id;
	}

	public void setCrt_id(String crt_id) {
		this.crt_id = crt_id;
	}

	public String getCrt_ip() {
		return crt_ip;
	}

	public void setCrt_ip(String crt_ip) {
		this.crt_ip = crt_ip;
	}

	public String getEnc_salt() {
		return enc_salt;
	}

	public void setEnc_salt(String enc_salt) {
		this.enc_salt = enc_salt;
	}

	public Date getUdt_date() {
		return udt_date;
	}

	public void setUdt_date(Date udt_date) {
		this.udt_date = udt_date;
	}

	public String getUdt_id() {
		return udt_id;
	}

	public void setUdt_id(String udt_id) {
		this.udt_id = udt_id;
	}

	public String getUdt_ip() {
		return udt_ip;
	}

	public void setUdt_ip(String udt_ip) {
		this.udt_ip = udt_ip;
	}

	public void setCp_cd(String cp_cd) {
		this.cp_cd = cp_cd;
	}
	
	public String getCp_cd() {
		return cp_cd;
	}
	
}
