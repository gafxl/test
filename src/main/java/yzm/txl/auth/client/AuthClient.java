/**
 *  Copyright (c) SHADANSOU 2014 All Rights Reserved
 *
 */
package yzm.txl.auth.client;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 鉴权客户端.
 * <p>
 * 
 * create 2014-8-7<br>
 * 
 * @author XZH<br>
 * @version Revision 2014-8-7
 * @since 1.0
 */
public class AuthClient {
	public static final int PASSWORD_MIN_LEN = 4;
	
	// 登陆验证： desc：用户名，密码，应用ID，应用秘钥登录
	public static String login(String domain, int port, String protocol, String user_name, String password,
			String client_id, String client_secret, String user_ip) {
		Map<String, String> paraMap = new HashMap<String, String>();

		// 密码截取
		if (null != password && password.length() > PASSWORD_MIN_LEN) {
			password = password.substring(0, password.length() - PASSWORD_MIN_LEN);
		}
		paraMap.put("user_name", user_name);
		paraMap.put("password", password);
		paraMap.put("client_id", client_id);
		paraMap.put("client_secret", client_secret);
		paraMap.put("user_ip", user_ip);
		return AuthRestUtil.postAuthServer(domain, port, protocol, "/auth/login/login", paraMap);
	}

	// 登出验证： access_token ip
	public static String logout(String domain, int port, String protocol,String access_token,String user_ip) {
		Map<String, String> paraMap = new HashMap<String, String>();

		paraMap.put("access_token", access_token);
		paraMap.put("user_ip", user_ip);
		return AuthRestUtil.postAuthServer(domain, port, protocol, "/auth/login/logout", paraMap);
	}

	/**
	 * 验证token access_token token值 remote_addr 请求的来源服务器地址 rest_id 请求的rest地址
	 */
	public static String verfiyToken(String domain, int port, String protocol, String access_token, String remote_addr,
			String rest_id,String rest_params,String user_ip) {
		Map<String, String> paraMap = new HashMap<String, String>();
		paraMap.put("access_token", access_token);
		paraMap.put("remote_addr", remote_addr);
		paraMap.put("rest_id", rest_id);
		paraMap.put("user_ip", user_ip);
		paraMap.put("rest_params", rest_params);
		return AuthRestUtil.postAuthServer(domain, port, protocol, "/auth/token/verify_token", paraMap);
	}

	/**
	 * 获取或者刷新token client_id 应用ID client_secret 应用secret grant_type
	 * client_credentials,refresh_token refresh_token 刷新token时使用
	 */
	public static String accessToken(String domain, int port, String protocol, String client_id, String client_secret,
			String grant_type, String refresh_token) {
		Map<String, String> paraMap = new HashMap<String, String>();
		paraMap.put("client_id", client_id);
		paraMap.put("client_secret", client_secret);
		paraMap.put("grant_type", grant_type);
		if (null != refresh_token) {
			paraMap.put("refresh_token", refresh_token);
		}
		return AuthRestUtil.postAuthServer(domain, port, protocol, "/auth/token/access_token", paraMap);

	}

}
