package caiyun;

import java.io.BufferedReader;

import java.io.IOException;

import java.io.InputStreamReader;

import java.io.OutputStream;

import java.net.HttpURLConnection;

import java.net.URL;

import java.nio.charset.Charset;

import java.util.HashMap;

import java.util.Map;

import java.util.concurrent.Executors;

import java.util.concurrent.ScheduledExecutorService;

import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;

public class OAuthDemo

{
	/** 申请授权tokenurl */
	private static final String OSE_GET_URL = "http://caiyun.feixin.10086.cn/authorize.jsp";
	/** 刷新授权tokenurl */
	private static final String OSE_REFRESH_URL = "https://ose.caiyun.feixin.10086.cn/oauthApp/OAuth2/refreshToken";
	/** 应用注册时得到的AppID */
	private static final String CLIENT_ID = "APP1a2Aoi3Q0001";
	/** 应用注册信息的中的AppKEY */
	private static final String CLIENT_PASS = "575533DDB6E3811C6DC7C54F662338D7";
	/** 获取到的授权码 */
	private static final String CODE = "D4BA43E61DA25B8EAE760D8298E12CAE7602446D75BC8B1B6002820929FCF105B74F60426462AF493A2E35F83B6C5328";
	/** 重定向地址，如果授权码申请请求参数中包含，则此处必须包含，而且必须与上次的参数一致 */
	private static final String REDIRECT_URI = "http://1ai123456.gicp.net:8088/cy/authorize.asp";
	// 以上常量值仅为示例，请按实际值填写。
	private static final String UTF8 = "UTF-8";

	private static Gson gson = new Gson();
	private volatile String token = null;
	private volatile String refreshToken = null;
	private String clientId;
	private String clientPass;

	/**
	 * 
	 * 构造函数.
	 * 
	 * @param clientId：即应用注册时得到的APPId
	 * 
	 * @param clientPass：即应用注册信息的中的appkey
	 * 
	 */

	public OAuthDemo(String clientId, String clientPass)

	{

		this.clientId = clientId;

		this.clientPass = clientPass;

	}

	/**
	 * 
	 * 获取当前授权token.
	 * 
	 * @return 当前授权token，null表示尚未得到
	 * 
	 */

	public String getToken()
	{
		return token;
	}

	/**
	 * 
	 * 向和彩云开放平台申请用户token
	 * 
	 * @param code：前面申请到的授权码
	 * 
	 * @param redirectUri：重定向地址，如果授权码申请请求参数中包含，则此处必须包含且与申请时的参数一致。
	 * 
	 */

	public void getTokenFromOse(String code, String redirectUri)

	{

		clearCachedToken();

		Map<String, String> headers = new HashMap<String, String>();

		headers.put("Content-Type", "application/x-www-form-urlencoded");

		headers.put("Authorization", calAuthHead());

		StringBuilder sb = new StringBuilder(100);

		sb.append("grant_type=authorization_code&code=");

		sb.append(code);

		sb.append("&redirect_uri=");

		sb.append(redirectUri);
		try
		{
			String result = sendhttpReq(OSE_GET_URL, sb.toString(), headers);
			if (result != null )
			{
				GetTokenRsp rsp = gson.fromJson(result.toString(), GetTokenRsp.class);
				if (rsp != null)
				{
					token = rsp.getAccess_token();
					refreshToken = rsp.getRefresh_token();
					// 如果需要长期保留访问token使之有效，需要启动定时任务，定期刷新。
					startRefreshTokenTask(rsp.getExpires_in());
				}
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * 访问token的有效时间到了之后，第3方应用需要拿刷新token换取新的访问token.
	 * 
	 */

	public void refreshToken()

	{
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		headers.put("Authorization", calAuthHead());
		StringBuilder sb = new StringBuilder(100);
		sb.append("grant_type=refresh_token&refresh_token=");
		sb.append(refreshToken);
		try
		{
			String result = sendhttpReq(OSE_REFRESH_URL, sb.toString(), headers);
			if (result != null)
			{
				RefreshTokenRsp rsp = gson.fromJson(result.toString(), RefreshTokenRsp.class);
				if (rsp != null)
				{
					token = rsp.getAccess_token();
					// 如果需要长期保留访问token使之有效，需要启动定时任务，定期刷新
					startRefreshTokenTask(rsp.getExpires_in());
				}
				else
				{
					clearCachedToken();
				}
			}
		}
		catch (IOException e)
		{
			clearCachedToken();
			e.printStackTrace();
		}

	}

	/**
	 *
	 * 
	 * 
	 * 刷新访问token任务.
	 * 
	 * @param expireTime：访问token所示的有效期
	 * 
	 */

	private void startRefreshTokenTask(int expireTime)

	{

		final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

		final Runnable refresher = new Runnable()

		{

			public void run()

			{

				refreshToken();

			}

		};

		scheduler.schedule(refresher, expireTime / 2/* 启动刷新的时间应该比超时时间提前些 */

				, TimeUnit.SECONDS);

	}

	/**
	 * 
	 * 构造Authorization头域内容.
	 * 
	 * @return
	 * 
	 */

	private String calAuthHead()

	{

		String res = clientId + ":" + clientPass;

		byte[] buf = Base64.encodeBase64(res.getBytes());

		return "Basic " + new String(buf, Charset.forName(UTF8));

	}

	/**
	 * 
	 * 清除缓存的授权token.
	 * 
	 */

	public void clearCachedToken()

	{

		token = null;

		refreshToken = null;

	}

	/**
	 * 
	 * 发送http请求.
	 * 
	 * @param url：请求url
	 * 
	 * @param httpStr：请求消息体
	 * 
	 * @param headers：请求消息头
	 * 
	 * @return http返回消息体，null表示失败
	 * 
	 * @throws IOException
	 * 
	 */

	private final String sendhttpReq(String url, String httpStr, Map<String, String> headers) throws IOException
	{
		HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
		con.setRequestMethod("POST");
		con.setDoOutput(true);
		con.setDoInput(true);
		if (headers != null)
		{
			for (Map.Entry<String, String> entry : headers.entrySet())
			{
				con.setRequestProperty(entry.getKey(), entry.getValue());
			}
		}
		OutputStream out = con.getOutputStream();
		out.write(httpStr.getBytes(UTF8));
		out.flush();
		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		if (200 != con.getResponseCode())
		{
			return null;
		}
		StringBuilder result = new StringBuilder(100);
		char[] buf = new char[512];
		int byteread = 0;
		while ((byteread = in.read(buf)) != -1)
		{
			result.append(buf, 0, byteread);
		}
		return result.toString();
	}

	/**
	 * 
	 * getToken的响应结构
	 * 
	 */
	private static class GetTokenRsp
	{
		private String access_token;
		private String token_type;
		private int expires_in;
		private String refresh_token;
		public String getAccess_token()
		{
			return access_token;
		}
		public String getToken_type()
		{
			return token_type;
		}
		public int getExpires_in()
		{
			return expires_in;
		}
		public String getRefresh_token()
		{
			return refresh_token;
		}
	}

	/**
	 * 
	 * refreshToken的响应结构
	 * 
	 */

	private static class RefreshTokenRsp
	{
		private String access_token;
		private String token_type;
		private int expires_in;
		public String getAccess_token()
		{
			return access_token;
		}
		public String getToken_type()
		{
			return token_type;
		}
		public int getExpires_in()
		{
			return expires_in;
		}
	}

	public static void main(String[] args) throws InterruptedException
	{
		OAuthDemo oauth = new OAuthDemo(CLIENT_ID, CLIENT_PASS);
		String token = oauth.getToken();
		if (token == null)
		{
			// 发起用户授权流程，获得授权码：CODE
			// 用授权码向和彩云开放平台申请用户token
			oauth.getTokenFromOse(CODE, REDIRECT_URI);
		}
		token = oauth.getToken();
		System.out.println(token);
	}
}
