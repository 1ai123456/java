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
	/** ������Ȩtokenurl */
	private static final String OSE_GET_URL = "http://caiyun.feixin.10086.cn/authorize.jsp";
	/** ˢ����Ȩtokenurl */
	private static final String OSE_REFRESH_URL = "https://ose.caiyun.feixin.10086.cn/oauthApp/OAuth2/refreshToken";
	/** Ӧ��ע��ʱ�õ���AppID */
	private static final String CLIENT_ID = "APP1a2Aoi3Q0001";
	/** Ӧ��ע����Ϣ���е�AppKEY */
	private static final String CLIENT_PASS = "575533DDB6E3811C6DC7C54F662338D7";
	/** ��ȡ������Ȩ�� */
	private static final String CODE = "D4BA43E61DA25B8EAE760D8298E12CAE7602446D75BC8B1B6002820929FCF105B74F60426462AF493A2E35F83B6C5328";
	/** �ض����ַ�������Ȩ��������������а�������˴�������������ұ������ϴεĲ���һ�� */
	private static final String REDIRECT_URI = "http://1ai123456.gicp.net:8088/cy/authorize.asp";
	// ���ϳ���ֵ��Ϊʾ�����밴ʵ��ֵ��д��
	private static final String UTF8 = "UTF-8";

	private static Gson gson = new Gson();
	private volatile String token = null;
	private volatile String refreshToken = null;
	private String clientId;
	private String clientPass;

	/**
	 * 
	 * ���캯��.
	 * 
	 * @param clientId����Ӧ��ע��ʱ�õ���APPId
	 * 
	 * @param clientPass����Ӧ��ע����Ϣ���е�appkey
	 * 
	 */

	public OAuthDemo(String clientId, String clientPass)

	{

		this.clientId = clientId;

		this.clientPass = clientPass;

	}

	/**
	 * 
	 * ��ȡ��ǰ��Ȩtoken.
	 * 
	 * @return ��ǰ��Ȩtoken��null��ʾ��δ�õ�
	 * 
	 */

	public String getToken()
	{
		return token;
	}

	/**
	 * 
	 * ��Ͳ��ƿ���ƽ̨�����û�token
	 * 
	 * @param code��ǰ�����뵽����Ȩ��
	 * 
	 * @param redirectUri���ض����ַ�������Ȩ��������������а�������˴����������������ʱ�Ĳ���һ�¡�
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
					// �����Ҫ���ڱ�������tokenʹ֮��Ч����Ҫ������ʱ���񣬶���ˢ�¡�
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
	 * ����token����Чʱ�䵽��֮�󣬵�3��Ӧ����Ҫ��ˢ��token��ȡ�µķ���token.
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
					// �����Ҫ���ڱ�������tokenʹ֮��Ч����Ҫ������ʱ���񣬶���ˢ��
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
	 * ˢ�·���token����.
	 * 
	 * @param expireTime������token��ʾ����Ч��
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

		scheduler.schedule(refresher, expireTime / 2/* ����ˢ�µ�ʱ��Ӧ�ñȳ�ʱʱ����ǰЩ */

				, TimeUnit.SECONDS);

	}

	/**
	 * 
	 * ����Authorizationͷ������.
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
	 * ����������Ȩtoken.
	 * 
	 */

	public void clearCachedToken()

	{

		token = null;

		refreshToken = null;

	}

	/**
	 * 
	 * ����http����.
	 * 
	 * @param url������url
	 * 
	 * @param httpStr��������Ϣ��
	 * 
	 * @param headers��������Ϣͷ
	 * 
	 * @return http������Ϣ�壬null��ʾʧ��
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
	 * getToken����Ӧ�ṹ
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
	 * refreshToken����Ӧ�ṹ
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
			// �����û���Ȩ���̣������Ȩ�룺CODE
			// ����Ȩ����Ͳ��ƿ���ƽ̨�����û�token
			oauth.getTokenFromOse(CODE, REDIRECT_URI);
		}
		token = oauth.getToken();
		System.out.println(token);
	}
}
