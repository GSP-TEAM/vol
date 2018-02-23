package kr.co.sicc.gsp.svm.gms.svm.dao;

import org.apache.ibatis.annotations.Param;

import kr.co.sicc.gsp.svm.gms.svm.vo.SVMUserVO;
import kr.co.sicc.gsp.svm.sicc.exception.SiccException;

public interface SVMUserDAO {

//	public List<Map<String, Object>> list(SVMUserVO vo);
//	public int total_cnt(SVMUserVO vo);
//	public Map<String, Object> edit(String user_id, String system_cd);
//	public int delete(String user_id, String system_cd);
//	public int delete_group(String user_id, String system_cd);
//	public List<Map<String, Object>> list_priv(SVMUserVO vo);
//	public void delete_priv(String user_id, String system_cd);
//	public List<Map<String, Object>> list_granted_priv(SVMUserVO vo);
//	public void delete_group_priv(String user_id, String system_cd);
//	public void insert_group(SVMUserVO vo) throws SiccException;

	public int update(SVMUserVO vo) throws SiccException;
	public void insert_priv(SVMUserVO vo) throws SiccException;
	public void insert_auth(SVMUserVO vo) throws SiccException;
	public void insert(SVMUserVO vo) throws SiccException;
	public int chk_email(@Param("tenant_id") String tenant_id, @Param("cp_cd") String cp_cd, @Param("email_id") String email_id)throws SiccException;
	public String chk_email_auth(String email)throws SiccException;
//	public void insert_history(SVMUserVO vo) throws SiccException;
}
