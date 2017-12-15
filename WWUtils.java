import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.beanutils.ConvertUtils;
import org.apache.commons.beanutils.Converter;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @author 王玮
 * @version 20.0
 * 工具类
 * 运行时间判断
 * 参数判空 1.12
 * 获取Treemap字典顺序集合
 * 获取payload对象
 * 映射rs到对象 (过时)
 * 自定义注解
 * 自定义日期转换器
 * 查询ip方法
 * httpclient发送模拟
 * 邮箱字符串判断
 * 发送邮件
 * 重写URLencoder decoder 1.2
 * 运行时间一对象为基础判断
 * 正则匹配器
 * RSA AES 加密解密工具 2.0
 * Base64编解码 2.0
 * 16进制编解码 1.2
 * 服务器特殊标识
 * md5工具 1.1
 * md5生成sign
 * 创建简单json
 * toString
 * 用户状态注解
 * 验证sign 
 * 生成简单insert sql
 * 生成简单updata sql
 * 生成随机数
 * rs封装到对象
 * 对象到json字符串
 */
public class WWUtils {

	/**
	 * 服务器标识
	 */
	public static String PROJECT_KEY = "jnxuqplyggfrbjsi";

	/**
	 * RSA公钥(base64编码字节码)
	 */
	private final static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgaWj5Ty2iqG6m3OIV4p34D0HiIWiHvvfQdofdIWTy+cCgag2kudvBGKVoDGhE8YQl6zfX4fJsyiR8nIdE0mFESBjbyPIAFxIOVUX2+Iqp1Y3v6842P4v608j8DXWANrsEypneD+ilAvmwjXdl8I2jbyTPt9xMHVLimqI9Z9fweQIDAQAB";

	/**
	 * RSA私钥(base64编码字节码)
	 */
	private final static String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKBpaPlPLaKobqbc4hXinfgPQeIhaIe+99B2h90hZPL5wKBqDaS528EYpWgMaETxhCXrN9fh8mzKJHych0TSYURIGNvI8gAXEg5VRfb4iqnVje/rzjY/i/rTyPwNdYA2uwTKmd4P6KUC+bCNd2XwjaNvJM+33EwdUuKaoj1n1/B5AgMBAAECgYALE/yJ6yvtpdAueearOEFMllEoesIrTcbzgJwVa277UMA609gpXiSNC1SxANpamItVyw7KO/JwDO3EJVM6L4VEA7M7fYvStDXDx4581IeMnnELZwjMTNdK0JFdj0D/NI3s4oYKhTMdwQOyTh7dtxtS1xcHg8wbbQkQgWk5IvnqAQJBAOcbnw7oyCjSLsjSlWmvUlv1/K68+C6J9fDSaqqYTn/Bv/80pb2r6pLoJlxrWHt5TuhLa7JwfasbGg9WASbVOyECQQCxsHjAaOhKFG8kP4xf44jpJyyWiYf0+eTEaNDtS+qyuWKiR2jIBSFflV4yVpxVr20qGEDn6saTctwzamiWXCJZAkEA1NAllvgaoSRy+nCYL7rHT3FkHpBaxZg7Bmjs2mzoFFMY9uvHF7LAjkkCUiZzUzgwxk31PVrDDhYl2CttYhIGoQJBAKflbKO6PMtKtZ3Voik00TglON9hQqL6wOvJcqjWFAUeYJGf0eU128v6UlBUQFJCeW7ODf5Ve571aBX5FKwGkLkCQA9lbm/fUE9c/Q4kn8N95EP+RLjrKWwlak/NGfuJDPNuq8/b3qTh3/KENVwU7Rvn3r7GqciJONS0yGmaFNF10qc=";

	private long startTimeO;

	private long endTimeO;

	public void startO() {
		startTimeO = System.currentTimeMillis();
	}

	public void endO() {
		endTimeO = System.currentTimeMillis();
		System.out.println("运行了" + (endTimeO - startTimeO) + "毫秒");
	}

	/**
	 * 开始运行时间
	 */
	private static long startTime;

	/**
	 * 开始运行标记
	 */
	private static boolean isStart = false;

	/**
	 * 结束运行时间
	 */
	private static long endTime;

	/**
	 * 结束运行标记
	 */
	private static boolean isEnd = false;

	/**
	 * 开始
	 */
	public static void start() {
		isStart = true;
		startTime = System.currentTimeMillis();
	}

	/**
	 * 结束 控制台输出结果
	 */
	public static void end() {
		isEnd = true;
		endTime = System.currentTimeMillis();
		System.out.println("运行了" + getRunTime() + "毫秒");
	}

	/**
	 * 获取运行时间
	 * @return 运行时间毫秒值
	 */
	private static long getRunTime() {
		if (!isStart || !isEnd) {
			isStart = false;
			isEnd = false;
			return -1l;
		}
		isStart = false;
		isEnd = false;
		return endTime - startTime;
	}

	/**
	 * 参数判空
	 * @param str
	 * @return
	 */
	public static boolean isBlank(String... str) {
		if (str.length == 0) {
			return true;
		}
		for (int i = 0; i < str.length; i++) {
			if (str[i] == null ? true : str[i].trim().equals("")) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 参数判空
	 * @param str "userID" "用户未登录" "password" "password为空"
	 * @return null : 不为空; 其他 : 提示信息
	 */
	public static String judgeBlank(String... str) {
		for (int i = 0; i < str.length; i++) {
			if (i % 2 == 0) {
				//要判断的值
				if (str[i] == null ? true : str[i].trim().equals("")) {
					return str[i + 1];
				}
			}
		}
		return null;
	}

	/**
	 * 参数判空
	 * @param str "userID" "用户未登录" "password" "password为空"
	 * @return null : 不为空; 其他 : json提示信息
	 */
	public static String judgeBlankJson(String... str) {
		for (int i = 0; i < str.length; i++) {
			if (i % 2 == 0) {
				//要判断的值
				if (str[i] == null ? true : str[i].trim().equals("")) {
					return "{\"state\":\"1\",\"message\":\"" + str[i + 1] + "\"}";
				}
			}
		}
		return null;
	}

	/**
	 * 封装验证sign map
	 */
	public static Map<String, String> createSignMap(String... str) {
		Map<String, String> returnMap = new TreeMap<String, String>();
		for (int i = 0; i < str.length; i++) {
			if (i % 2 == 0) {
				returnMap.put(str[i], str[i + 1]);
			}
		}
		return returnMap;
	}

	/**
	 * 封装全部对象(包含空payload体)
	 * @throws FileUploadException 
	 * 
	 */
	public static List<FileItem> getAllFileItemsFromPayload(HttpServletRequest request, long size) throws FileUploadException {
		DiskFileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload servletFileUpload = new ServletFileUpload(factory);
		servletFileUpload.setFileSizeMax(size);
		List<FileItem> fileItems = servletFileUpload.parseRequest(request);
		return fileItems;
	}

	/**
	 * 封装payload表单数据(已过时)
	 * @param request 
	 * @param size 允许上传的最大字节
	 * @return map<String,String>
	 * @throws FileUploadException
	 * @throws UnsupportedEncodingException
	 */
	@Deprecated
	public static Map<String, String> getFormsFromPayload(HttpServletRequest request, long size) throws FileUploadException, UnsupportedEncodingException {
		Map<String, String> map = new HashMap<String, String>();//封装表单字段
		DiskFileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload servletFileUpload = new ServletFileUpload(factory);
		servletFileUpload.setFileSizeMax(size);
		List<FileItem> fileItems = servletFileUpload.parseRequest(request);
		for (FileItem fileItem : fileItems) {
			if (fileItem.getSize() == 0) {
				//字段未空 跳过
				continue;
			}
			if (fileItem.isFormField()) {
				//是form字段参数
				String key = fileItem.getFieldName();
				String value = fileItem.getString("UTF-8");
				map.put(key, value);
			} else {
				//不是form字段参数
			}
		}
		return map;
	}

	/**
	 * 获得FileItems中的表单数据
	 * @param fileItems 
	 * @throws UnsupportedEncodingException UTF-8转换错误 
	 * @return 
	 */
	public static Map<String, String> getFormsFromFileItems(List<FileItem> fileItems) throws UnsupportedEncodingException {
		Map<String, String> map = new HashMap<String, String>();//封装表单字段
		for (FileItem fileItem : fileItems) {
			if (fileItem.getSize() == 0) {
				//字段未空 跳过
				continue;
			}
			if (fileItem.isFormField()) {
				//是form字段参数
				String key = fileItem.getFieldName();
				String value = fileItem.getString("UTF-8");
				map.put(key, value);
			} else {
				//不是form字段参数
			}
		}
		return map;
	}

	/**
	 * 封装payload实体数据(已过时)
	 * @param request
	 * @param size
	 * @return List<FileItem>
	 * @throws FileUploadException 上传错误
	 */
	@Deprecated
	public static List<FileItem> getEntityItemFromPayload(HttpServletRequest request, long size) throws FileUploadException {
		List<FileItem> fileItemList = new ArrayList<FileItem>();//封装实体对象
		DiskFileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload servletFileUpload = new ServletFileUpload(factory);
		servletFileUpload.setFileSizeMax(size);
		List<FileItem> fileItems = servletFileUpload.parseRequest(request);
		for (FileItem fileItem : fileItems) {
			if (fileItem.getSize() == 0) {
				//字段未空 跳过
				continue;
			}
			if (fileItem.isFormField()) {
				//是form字段参数
			} else {
				//不是form字段参数
				fileItemList.add(fileItem);
			}
		}
		return fileItemList;
	}

	/**
	 * 获得FileItems中的实体对象
	 * @param fileItems
	 * @return
	 */
	public static List<FileItem> getEntityItemFromFileItems(List<FileItem> fileItems) {
		List<FileItem> returnFileItemList = new ArrayList<FileItem>();//封装实体对象
		for (FileItem fileItem : fileItems) {
			if (fileItem.getSize() == 0) {
				//字段未空 跳过
				continue;
			}
			if (fileItem.isFormField()) {
				//是form字段参数
			} else {
				//不是form字段参数
				returnFileItemList.add(fileItem);
			}
		}
		return returnFileItemList;
	}

	/**
	 * 获得FileItems中的空体对象
	 * @param fileItems
	 * @return
	 */
	public static List<FileItem> getEmptyBodyItemsFromFileItems(List<FileItem> fileItems) {
		List<FileItem> returnFileItemList = new ArrayList<FileItem>();//封装空体对象
		for (FileItem fileItem : fileItems) {
			if (fileItem.getSize() == 0) {
				//字段未空->添加
				returnFileItemList.add(fileItem);
				continue;
			} else {
				//字段不为空->跳过
			}
		}
		return returnFileItemList;
	}

	/**
	 * 将结果集resultSet映射成为javabean
	 * @param rs 数据库查询数据的结果集
	 * @param clazz 需要映射成为的javaBean的class 注解DbColumn表示查找到的字段名 如不需要处理添加
	 * @return 一个携带javaBean的List
	 * @throws Exception
	 */
	@Deprecated
	public static <T> List<T> ColumnToField(ResultSet rs, Class<T> clazz) throws Exception {
		T obj = clazz.newInstance();
		Field[] fields = clazz.getDeclaredFields();
		List<T> list = new ArrayList<T>();
		while (rs.next()) {
			obj = clazz.newInstance();
			for (Field f : fields) {
				//得到字段名
				String name = f.getName();
				//默认情况下列名等于javaBean里的属性的值
				String columnName = new String(name);
				//得到字段类型
				Class type = f.getType();
				//判断字段上是否有注解
				if (f.isAnnotationPresent(DbColumn.class)) {
					//获取字段上column注解的值,并附值给列名
					if (f.getAnnotation(DbColumn.class).value().equals("")) {
						//为空则默认为字段名
					} else {
						columnName = f.getAnnotation(DbColumn.class).value();
					}
				} else {
					//没有注解
					continue;
				}
				Method method = null;
				try {
					//反射得到javaBean每个字段的set方法
					method = clazz.getMethod("set" + name.replaceFirst(name.substring(0, 1), name.substring(0, 1).toUpperCase()), type);
					//注册时间类型转换器
					ConvertUtils.register(new MyConvert(), Date.class);
					//调用set方法为对象设置值
					method.invoke(obj, ConvertUtils.convert(rs.getString(columnName), type));
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			list.add(obj);
		}
		return list;
	}

	/**
	 * 自定义字段映射数据库名(别名)
	 */
	@Target({ ElementType.METHOD, ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface DbColumn {
		/**
		 * 映射的列名
		 * @return
		 */
		String value();
	}

	/**
	 * 自定义时间格式转换器
	 */
	public static class MyConvert implements Converter {
		@Override
		public Object convert(Class type, Object value) {
			if (value == null)
				return null;
			if (!type.toString().equals("class java.util.Date"))
				return (String) value;

			String str = (String) value;
			SimpleDateFormat smDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			try {
				Date date = smDateFormat.parse(str);
				return date;
			} catch (ParseException e) {
				e.printStackTrace();
			}
			return null;
		}
	}

	/**
	 * base64编码标识
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface Base64 {
	}

	/**
	 * 全部DbBase64注解字段编码
	 * @throws Exception 
	 */
	public static <T> void base64EncodeAllBase64(T t) throws Exception {
		Field[] fields = t.getClass().getDeclaredFields();
		try {
			for (Field field : fields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.Base64.class)) {
					String fieldData = (String) field.get(t);
					if (fieldData != null && !WWUtils.isBlank(fieldData)) {
						field.set(t, WWUtils.base64Encode(fieldData, "UTF-8"));
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 全部DbBase64注解字段解码
	 * @throws Exception 
	 */
	public static <T> void base64DecodeAllBase64(T t) throws Exception {
		Field[] fields = t.getClass().getDeclaredFields();
		try {
			for (Field field : fields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.Base64.class)) {
					String fieldData = (String) field.get(t);
					if (fieldData != null && !WWUtils.isBlank(fieldData)) {
						field.set(t, WWUtils.base64Decode(fieldData, "UTF-8"));
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 根据ip获取解析ip地址详细信息
	 * 默认访问量1000
	 * ip138地址
	 * @param ip
	 * @return json字符串
	 */
	public static String queryIP(String ip) {
		String url = "http://api.ip138.com/query/?ip=" + ip;
		String token = "859476648b3de65d76804906dd1a1c6a";
		return get(url, token);
	}

	/**
	 * 获取json字符串
	 * @param urlString
	 * @param token
	 * @return
	 */
	public static String get(String urlString, String token) {
		try {
			URL url = new URL(urlString);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setConnectTimeout(5 * 1000);
			conn.setReadTimeout(5 * 1000);
			conn.setDoInput(true);
			conn.setDoOutput(true);
			conn.setUseCaches(false);
			conn.setInstanceFollowRedirects(false);
			conn.setRequestMethod("GET");
			conn.setRequestProperty("token", token);
			int responseCode = conn.getResponseCode();
			if (responseCode == 200) {
				StringBuilder builder = new StringBuilder();
				BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
				for (String s = br.readLine(); s != null; s = br.readLine()) {
					builder.append(s);
				}
				br.close();
				return builder.toString();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 封装HTTP POST方法
	 * 
	 * @param
	 * @param
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String post(String url, Map<String, String> paramMap) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpPost httpPost = new HttpPost(url);
		List<NameValuePair> formparams = setHttpParams(paramMap);
		UrlEncodedFormEntity param = new UrlEncodedFormEntity(formparams, "UTF-8");
		httpPost.setEntity(param);
		HttpResponse response = httpClient.execute(httpPost);
		String httpEntityContent = getHttpEntityContent(response);
		httpPost.abort();
		return httpEntityContent;
	}

	/**
	 * 封装HTTP POST方法
	 * 
	 * @param
	 * @param （如JSON串）
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String post(String url, String data) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpPost httpPost = new HttpPost(url);
		httpPost.setHeader("Content-Type", "text/json; charset=utf-8");
		httpPost.setEntity(new StringEntity(URLEncoder.encode(data, "UTF-8")));
		HttpResponse response = httpClient.execute(httpPost);
		String httpEntityContent = getHttpEntityContent(response);
		httpPost.abort();
		return httpEntityContent;
	}

	/**
	 * 封装HTTP GET方法
	 * 
	 * @param
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String get(String url) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpGet httpGet = new HttpGet();
		httpGet.setURI(URI.create(url));
		HttpResponse response = httpClient.execute(httpGet);
		String httpEntityContent = getHttpEntityContent(response);
		httpGet.abort();
		return httpEntityContent;
	}

	/**
	 * 封装HTTP GET方法
	 * 
	 * @param
	 * @param
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String get(String url, Map<String, String> paramMap) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpGet httpGet = new HttpGet();
		List<NameValuePair> formparams = setHttpParams(paramMap);
		String param = URLEncodedUtils.format(formparams, "UTF-8");
		httpGet.setURI(URI.create(url + "?" + param));
		HttpResponse response = httpClient.execute(httpGet);
		String httpEntityContent = getHttpEntityContent(response);
		httpGet.abort();
		return httpEntityContent;
	}

	/**
	 * 封装HTTP PUT方法
	 * 
	 * @param
	 * @param
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String put(String url, Map<String, String> paramMap) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpPut httpPut = new HttpPut(url);
		List<NameValuePair> formparams = setHttpParams(paramMap);
		UrlEncodedFormEntity param = new UrlEncodedFormEntity(formparams, "UTF-8");
		httpPut.setEntity(param);
		HttpResponse response = httpClient.execute(httpPut);
		String httpEntityContent = getHttpEntityContent(response);
		httpPut.abort();
		return httpEntityContent;
	}

	/**
	 * 封装HTTP DELETE方法
	 * 
	 * @param
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String delete(String url) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpDelete httpDelete = new HttpDelete();
		httpDelete.setURI(URI.create(url));
		HttpResponse response = httpClient.execute(httpDelete);
		String httpEntityContent = getHttpEntityContent(response);
		httpDelete.abort();
		return httpEntityContent;
	}

	/**
	 * 封装HTTP DELETE方法
	 * 
	 * @param
	 * @param
	 * @return
	 * @throws ClientProtocolException
	 * @throws java.io.IOException
	 */
	public static String delete(String url, Map<String, String> paramMap) throws ClientProtocolException, IOException {
		HttpClient httpClient = new DefaultHttpClient();
		HttpDelete httpDelete = new HttpDelete();
		List<NameValuePair> formparams = setHttpParams(paramMap);
		String param = URLEncodedUtils.format(formparams, "UTF-8");
		httpDelete.setURI(URI.create(url + "?" + param));
		HttpResponse response = httpClient.execute(httpDelete);
		String httpEntityContent = getHttpEntityContent(response);
		httpDelete.abort();
		return httpEntityContent;
	}

	/**
	 * 设置请求参数
	 * 
	 * @param
	 * @return
	 */
	private static List<NameValuePair> setHttpParams(Map<String, String> paramMap) {
		List<NameValuePair> formparams = new ArrayList<NameValuePair>();
		Set<Map.Entry<String, String>> set = paramMap.entrySet();
		for (Map.Entry<String, String> entry : set) {
			formparams.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
		}
		return formparams;
	}

	/**
	 * 获得响应HTTP实体内容
	 * 
	 * @param response
	 * @return
	 * @throws java.io.IOException
	 * @throws java.io.UnsupportedEncodingException
	 */
	private static String getHttpEntityContent(HttpResponse response) throws IOException, UnsupportedEncodingException {
		HttpEntity entity = response.getEntity();
		if (entity != null) {
			InputStream is = entity.getContent();
			BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
			String line = br.readLine();
			StringBuilder sb = new StringBuilder();
			while (line != null) {
				sb.append(line + "\n");
				line = br.readLine();
			}
			return sb.toString();
		}
		return "";
	}

	/**
	 * 1.地址中不包括@ 或 .
	 * 2.地址中包括多个 @ 或 .
	 * 3.邮箱地址中 . 出现 在@ 前面
	 * 4.用户名中出现其他字符
	 */
	public static boolean testMail(String strMail) {

		if (strMail.indexOf("@") == -1 || strMail.indexOf(".") == -1) {
			return false;
		}

		if (strMail.indexOf("@") != strMail.lastIndexOf("@") || strMail.indexOf(".") != strMail.lastIndexOf(".")) {
			return false;
		}

		if (strMail.indexOf("@") > strMail.indexOf(".")) {
			return false;
		}

		for (int i = 0; i < strMail.indexOf("@"); i++) {
			if (!((strMail.charAt(i) >= 'A' && strMail.charAt(i) <= 'Z') //
					|| (strMail.charAt(i) >= 'a' && strMail.charAt(i) <= 'z')//
			|| (strMail.charAt(i) >= '0' && strMail.charAt(i) <= '9'))) {
				return false;
			}
		}

		return true;
	}

	/**
	 * 发送邮件
	 * @param to_mail 邮箱
	 * @param to_title 标题
	 * @param to_content 主体1 (弃用)
	 * @param txt (主体)
	 * @return
	 * @throws MessagingException 发送失败
	 */
	public static void sendEmail(String to_mail, String to_title, String to_content) throws MessagingException {
		try {
			//建立邮件会话
			Properties props = new Properties();//也可用Properties props = System.getProperties(); 
			props.put("mail.smtp.host", "smtp.139.com");//存储发�?邮件服务器的信息
			props.put("mail.smtp.auth", "true");//同时通过验证
			Session s = Session.getInstance(props);//根据属�?新建�?��邮件会话
			s.setDebug(false);

			//由邮件会话新建一个消息对�?
			MimeMessage message = new MimeMessage(s);//由邮件会话新建一个消息对�?

			//设置邮件
			InternetAddress from = new InternetAddress("admin@kltong.me");
			message.setFrom(from);//设置发件�?
			InternetAddress to = new InternetAddress(to_mail);
			message.setRecipient(Message.RecipientType.TO, to);//设置收件�?并设置其接收类型为TO
			message.setSubject(to_title);//设置主题
			//message.setText(to_content);//设置信件内容
			message.setContent(to_content, "text/html; charset=utf-8");
			message.setSentDate(new Date());//设置发信时间

			//发�?邮件
			message.saveChanges();//存储邮件信息 
			Transport transport = s.getTransport("smtp");
			//以smtp方式登录邮箱,第一个参数是发�?邮件用的邮件服务器SMTP地址,第二个参数为用户�?第三个参数为密码
			transport.connect("smtp.ym.163.com", "admin@kltong.me", "810318");
			transport.sendMessage(message, message.getAllRecipients());//发�?邮件,其中第二个参数是�?��已设好的收件人地�?
			transport.close();
		} catch (MessagingException e) {
			System.out.println("发送失败" + e);
			throw e;
		}
	}

	/**
	 * 自定义URL编码
	 * @param str
	 * @param enc
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String URIEncode(String str, String enc) throws UnsupportedEncodingException {
		String encode = URLEncoder.encode(str, enc).replace("+", "%20");
		return encode;
	}

	/**
	 * 自定义URL解码
	 * @param str
	 * @param enc
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String URIDecode(String str, String enc) throws UnsupportedEncodingException {
		String decode = URLDecoder.decode(str, enc);
		return decode;
	}

	/**
	 * 正则匹配器
	 */
	public static String Matcher(String regex, String string) {
		//String rex = "[\u4e00-\u9fa5]|[0123456789]|[a-z]|[A-Z]";//匹配中文等
		StringBuilder returnstr = new StringBuilder();
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(string);
		while (matcher.find()) {
			returnstr.append(matcher.group());
		}
		return returnstr.toString();
	}

	/**
	 * 正则存在判断器
	 */
	public static boolean isMatcher(String regex, String string) {
		if (Matcher(regex, string).length() > 0) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * 多空格变单空格
	 */
	public static String moreBlank2OneBlank(String str) {
		str = str.trim();
		//sql替换为单空格
		Pattern p = Pattern.compile("\\s{2,}|\t");
		Matcher m = p.matcher(str);
		String strNoBlank = m.replaceAll(" ");
		return strNoBlank;
	}

	/**
	 * sql server 数据库关键字
	 */
	private final static String[] SQL_MAIN_WORDS = { "TOP", "DISTINCT", "VARP", "VAR", "SUM", "STDEVP", "STDEV", "MIN", "MAX", "COUNT", "AVG", "COMPUTE", "ORDER", "BY", "GROUP", "EXISTS", "ANY", "SOME", "ALL", "IN", "NULL", "NOT", "IS", "AND", "BETWEEN", "HAVING", "WHERE", "ADD", "EXCEPT", "PERCENTALL", "EXEC", "PLANALTER", "EXECUTE", "PRECISIONAND", "EXISTS", "PRIMARYANY", "EXIT", "PRINTAS", "FETCH", "PROCASC", "FILE", "PROCEDUREAUTHORIZATION", "FILLFACTOR", "PUBLICBACKUP", "FOR", "RAISERRORBEGIN", "FOREIGN", "READBETWEEN", "FREETEXT", "READTEXTBREAK", "FREETEXTTABLE", "RECONFIGUREBROWSE", "FROM", "REFERENCESBULK", "FULL", "REPLICATIONBY", "FUNCTION", "RESTORECASCADE", "GOTO", "RESTRICTCASE", "GRANT", "RETURNCHECK", "GROUP", "REVOKECHECKPOINT", "HAVING", "RIGHTCLOSE", "HOLDLOCK",
			"ROLLBACKCLUSTERED", "IDENTITY", "ROWCOUNTCOALESCE", "IDENTITY_INSERT", "ROWGUIDCOLCOLLATE", "IDENTITYCOL", "RULECOLUMN", "IF", "SAVECOMMIT", "IN", "SCHEMACOMPUTE", "INDEX", "SELECTCONSTRAINT", "INNER", "SESSION_USERCONTAINS", "INSERT", "SETCONTAINSTABLE", "INTERSECT", "SETUSERCONTINUE", "INTO", "SHUTDOWNCONVERT", "IS", "SOMECREATE", "JOIN", "STATISTICSCROSS", "KEY", "SYSTEM_USERCURRENT", "KILL", "TABLECURRENT_DATE", "LEFT", "TEXTSIZECURRENT_TIME", "LIKE", "THENCURRENT_TIMESTAMP", "LINENO", "TOCURRENT_USER", "LOAD", "TOPCURSOR", "NATIONAL", "TRANDATABASE", "NOCHECK", "TRANSACTIONDBCC", "NONCLUSTERED", "TRIGGERDEALLOCATE", "NOT", "TRUNCATEDECLARE", "NULL", "TSEQUALDEFAULT", "NULLIF", "UNIONDELETE", "OF", "UNIQUEDENY", "OFF", "UPDATEDESC", "OFFSETS", "UPDATETEXTDISK", "ON",
			"USEDISTINCT", "OPEN", "USERDISTRIBUTED", "OPENDATASOURCE", "VALUESDOUBLE", "OPENQUERY", "VARYINGDROP", "OPENROWSET", "VIEWDUMMY", "OPENXML", "WAITFORDUMP", "OPTION", "WHENELSE", "OR", "WHEREEND", "ORDER", "WHILEERRLVL", "OUTER", "WITHESCAPE", "OVER", "WRITETEXTABSOLUTE", "EXEC", "OVERLAPSACTION", "EXECUTE", "PADADA", "EXISTS", "PARTIALADD", "EXTERNAL", "PASCALALL", "EXTRACT", "POSITIONALLOCATE", "FALSE", "PRECISIONALTER", "FETCH", "PREPAREAND", "FIRST", "PRESERVEANY", "FLOAT", "PRIMARYARE", "FOR", "PRIORAS", "FOREIGN", "PRIVILEGESASC", "FORTRAN", "PROCEDUREASSERTION", "FOUND", "PUBLICAT", "FROM", "READAUTHORIZATION", "FULL", "REALAVG", "GET", "REFERENCESBEGIN", "GLOBAL", "RELATIVEBETWEEN", "GO", "RESTRICTBIT", "GOTO", "REVOKEBIT_LENGTH", "GRANT", "RIGHTBOTH", "GROUP",
			"ROLLBACKBY", "HAVING", "ROWSCASCADE", "HOUR", "SCHEMACASCADED", "IDENTITY", "SCROLLCASE", "IMMEDIATE", "SECONDCAST", "IN", "SECTIONCATALOG", "INCLUDE", "SELECTCHAR", "INDEX", "SESSIONCHAR_LENGTH", "INDICATOR", "SESSION_USERCHARACTER", "INITIALLY", "SETCHARACTER_LENGTH", "INNER", "SIZECHECK", "INPUT", "SMALLINTCLOSE", "INSENSITIVE", "SOMECOALESCE", "INSERT", "SPACECOLLATE", "INT", "SQLCOLLATION", "INTEGER", "SQLCACOLUMN", "INTERSECT", "SQLCODECOMMIT", "INTERVAL", "SQLERRORCONNECT", "INTO", "SQLSTATECONNECTION", "IS", "SQLWARNINGCONSTRAINT", "ISOLATION", "SUBSTRINGCONSTRAINTS", "JOIN", "SUMCONTINUE", "KEY", "SYSTEM_USERCONVERT", "LANGUAGE", "TABLECORRESPONDING", "LAST", "TEMPORARYCOUNT", "LEADING", "THENCREATE", "LEFT", "TIMECROSS", "LEVEL", "TIMESTAMPCURRENT", "LIKE",
			"TIMEZONE_HOURCURRENT_DATE", "LOCAL", "TIMEZONE_MINUTECURRENT_TIME", "LOWER", "TOCURRENT_TIMESTAMP", "MATCH", "TRAILINGCURRENT_USER", "MAX", "TRANSACTIONCURSOR", "MIN", "TRANSLATEDATE", "MINUTE", "TRANSLATIONDAY", "MODULE", "TRIMDEALLOCATE", "MONTH", "TRUEDEC", "NAMES", "UNIONDECIMAL", "NATIONAL", "UNIQUEDECLARE", "NATURAL", "UNKNOWNDEFAULT", "NCHAR", "UPDATEDEFERRABLE", "NEXT", "UPPERDEFERRED", "NO", "USAGEDELETE", "NONE", "USERDESC", "NOT", "USINGDESCRIBE", "NULL", "VALUEDESCRIPTOR", "NULLIF", "VALUESDIAGNOSTICS", "NUMERIC", "VARCHARDISCONNECT", "OCTET_LENGTH", "VARYINGDISTINCT", "OF", "VIEWDOMAIN", "ON", "WHENDOUBLE", "ONLY", "WHENEVERDROP", "OPEN", "WHEREELSE", "OPTION", "WITHEND", "OR", "WORKEND-EXEC", "ORDER", "WRITEESCAPE", "OUTER", "YEAREXCEPT", "OUTPUT",
			"ZONEEXCEPTIONABSOLUTE", "FOUND", "PRESERVEACTION", "FREE", "PRIORADMIN", "GENERAL", "PRIVILEGESAFTER", "GET", "READSAGGREGATE", "GLOBAL", "REALALIAS", "GO", "RECURSIVEALLOCATE", "GROUPING", "REFARE", "HOST", "REFERENCINGARRAY", "HOUR", "RELATIVEASSERTION", "IGNORE", "RESULTAT", "IMMEDIATE", "RETURNSBEFORE", "INDICATOR", "ROLEBINARY", "INITIALIZE", "ROLLUPBIT", "INITIALLY", "ROUTINEBLOB", "INOUT", "ROWBOOLEAN", "INPUT", "ROWSBOTH", "INT", "SAVEPOINTBREADTH", "INTEGER", "SCROLLCALL", "INTERVAL", "SCOPECASCADED", "ISOLATION", "SEARCHCAST", "ITERATE", "SECONDCATALOG", "LANGUAGE", "SECTIONCHAR", "LARGE", "SEQUENCECHARACTER", "LAST", "SESSIONCLASS", "LATERAL", "SETSCLOB", "LEADING", "SIZECOLLATION", "LESS", "SMALLINTCOMPLETION", "LEVEL", "SPACECONNECT", "LIMIT",
			"SPECIFICCONNECTION", "LOCAL", "SPECIFICTYPECONSTRAINTS", "LOCALTIME", "SQLCONSTRUCTOR", "LOCALTIMESTAMP", "SQLEXCEPTIONCORRESPONDING", "LOCATOR", "SQLSTATECUBE", "MAP", "SQLWARNINGCURRENT_PATH", "MATCH", "STARTCURRENT_ROLE", "MINUTE", "STATECYCLE", "MODIFIES", "STATEMENTDATA", "MODIFY", "STATICDATE", "MODULE", "STRUCTUREDAY", "MONTH", "TEMPORARYDEC", "NAMES", "TERMINATEDECIMAL", "NATURAL", "THANDEFERRABLE", "NCHAR", "TIMEDEFERRED", "NCLOB", "TIMESTAMPDEPTH", "NEW", "TIMEZONE_HOURDEREF", "NEXT", "TIMEZONE_MINUTEDESCRIBE", "NO", "TRAILINGDESCRIPTOR", "NONE", "TRANSLATIONDESTROY", "NUMERIC", "TREATDESTRUCTOR", "OBJECT", "TRUEDETERMINISTIC", "OLD", "UNDERDICTIONARY", "ONLY", "UNKNOWNDIAGNOSTICS", "OPERATION", "UNNESTDISCONNECT", "ORDINALITY", "USAGEDOMAIN", "OUT", "USINGDYNAMIC",
			"OUTPUT", "VALUEEACH", "PAD", "VARCHAREND-EXEC", "PARAMETER", "VARIABLEEQUALS", "PARAMETERS", "WHENEVEREVERY", "PARTIAL", "WITHOUTEXCEPTION", "PATH", "WORKEXTERNAL", "POSTFIX", "WRITEFLASE", "PREFIX", "YEARFIRST", "PREORDER", "ZONEFLOAT", "PREPARE" };

	/**
	 * 根据sql生成分页sql
	 * @author 王玮
	 * @param sql 未分页的sql
	 * @param pageNum 页数
	 * @param showNum 每页显示的条目
	 * @return
	 */
	@Deprecated
	public static String createLimitSql(String sql, int pageNum, int showNum) {
		String primanyKey = "fID";

		//去多余空格
		sql = moreBlank2OneBlank(sql);

		//封装sql到list
		List<String> listUpperCase = Arrays.asList(sql.toUpperCase().split(" "));
		List<String> list = Arrays.asList(sql.split(" "));

		//获取主表名
		String tableName = list.get(listUpperCase.indexOf("FROM") + 1);

		String key = "";

		//判断长度
		if (listUpperCase.size() - 1 > (listUpperCase.indexOf("FROM") + 1)) {
			//还有数据//->判断后一位是否是as
			if (list.get(listUpperCase.indexOf("FROM") + 2).toUpperCase().equals("AS")) {
				//是as 获取昵称
				key = list.get(listUpperCase.indexOf("FROM") + 3) + "." + primanyKey;
			} else {
				//不是as//->判断是否是sql关键字
				if (Arrays.asList(SQL_MAIN_WORDS).indexOf(list.get(listUpperCase.indexOf("FROM") + 2).toUpperCase()) == -1) {
					//不是sql关键字//->是昵称
					key = list.get(listUpperCase.indexOf("FROM") + 2) + "." + primanyKey;
				} else {
					//是sql关键字//->无昵称
					key = tableName + "." + primanyKey;
				}
			}
		} else {
			//无数据
			key = tableName + "." + primanyKey;
		}

		//获取页数参数
		String topX = " top " + showNum + " ";
		String topY = " top " + ((pageNum - 1) * showNum) + " " + key + " ";
		//定义返回变量
		StringBuilder returnSbu = new StringBuilder(sql);
		returnSbu.insert(returnSbu.toString().toUpperCase().indexOf("SELECT") + "SELECT".length(), topX);

		//条件语句 删除查询内容
		StringBuilder termStr = new StringBuilder("SELECT ");
		termStr.append(sql.substring(sql.toUpperCase().indexOf("FROM")));

		termStr.insert(returnSbu.toString().toUpperCase().indexOf("SELECT") + "SELECT".length(), topY);
		if (isMatcher("WHERE", sql.toUpperCase())) {
			//有where
			termStr.insert(0, " and " + key + " NOT IN (");
			termStr.append(") ");
			if (isMatcher("ORDER BY", sql)) {
				//有order by
				returnSbu.insert(returnSbu.toString().toUpperCase().indexOf("ORDER"), termStr);
			} else {
				//没有order by
				/*String returnStrUp = noBlank(returnSbu.toString().toUpperCase());
				String returnStr = noBlank(returnSbu.toString().toUpperCase());
				List<String> returnStrUpList = Arrays.asList(returnStrUp.split(" "));
				List<String> returnStrList = Arrays.asList(returnStr.split(" "));
				int whereIndex = returnStrUpList.indexOf("WHERE");
				boolean andFlag = false;
				for(int i = 1 ; i < 7 ;i++){
					if(returnStrUpList.get(whereIndex + i).equals("AND")){
						andFlag = true;
					}
				}
				if(andFlag){
					//有and
					
				}else{
					//无and
					
				}*/
				//->添加到where后最后一个and后或者where后
				returnSbu.append(termStr);
			}
		} else {
			//没有where
			termStr.insert(0, " where " + key + " NOT IN (");
			termStr.append(") ");
			if (isMatcher("ORDER BY", sql)) {
				//有order by
				returnSbu.insert(returnSbu.toString().toUpperCase().indexOf("ORDER"), termStr);
			} else {
				//没有order by
				returnSbu.append(termStr);
			}
		}

		return returnSbu.toString();
	}

	/**
	 * AES加密
	 * @param content 明文字节数组
	 * @param key 秘钥
	 * @param iv 初始向量
	 * @return 加密后字节数组
	 * @throws Exception
	 */
	public static byte[] AESEncrypt(byte[] content, byte[] key, byte[] iv) throws Exception {
		try {
			//秘钥参数
			Key keySpec = new SecretKeySpec(key, "AES"); //两个参数，第一个为私钥字节数组， 第二个为加密方式 "AES"或者"DES"

			//初始化向量参数AES 为16bytes. DES 为8bytes.
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			//创建密码对象
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//指定要初始化参数及"解码模式"
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

			//执行
			byte[] byteResult = cipher.doFinal(content);

			return byteResult;
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES解密
	 * @param content 密文字节数组
	 * @param key 秘钥
	 * @param iv 初始向量
	 * @return 解密后明文字节数组
	 * @throws Exception
	 */
	public static byte[] AESDecrypt(byte[] content, byte[] key, byte[] iv) throws Exception {
		try {

			//秘钥参数
			Key keySpec = new SecretKeySpec(key, "AES"); //两个参数，第一个为私钥字节数组， 第二个为加密方式 "AES"或者"DES"

			//初始化向量参数
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			//创建密码对象
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//指定要初始化参数及"解码模式"
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

			//执行
			byte[] byteResult = cipher.doFinal(content);

			return byteResult;
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES加密简单版
	 * @param content 原文字符串
	 * @param key 秘钥
	 * @param charsetName 字符串编码格式
	 * @return 加密后字节码 字节数组
	 */
	public static byte[] AESEncrypt(String content, String key, String charsetName) throws Exception {
		try {
			if (key.getBytes().length != 16) {
				throw new Exception("秘钥必须位16位字节");
			}
			return AESEncrypt(content.getBytes(charsetName), key.getBytes(), key.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES解密简单版
	 * @param content 密文字节码 字节数组
	 * @param key 秘钥
	 * @param charsetName 原加密字符串编码方式
	 * @return 原文解密后utf-8编码(秘钥要求16位bytes) 初始化向量为"1234567890123456"
	 */
	public static String AESDecrypt(byte[] content, String key, String charsetName) throws Exception {
		try {
			if (key.getBytes().length != 16) {
				throw new Exception("秘钥必须位16位字节");
			}

			byte[] aesDecryptBytes = AESDecrypt(content, key.getBytes(), key.getBytes());
			return new String(aesDecryptBytes, charsetName);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES加密为16进制字符串
	 * @param content 原文字符串
	 * @param key
	 * @param charsetName 原文字符编码方式
	 * @return 加密后的字节码16进制表示形式
	 * @throws Exception
	 */
	public static String AESEncrypt2HexStr(String content, String key, String charsetName) throws Exception {
		byte[] aesEncrypt = AESEncrypt(content, key, charsetName);
		return HexEncode(aesEncrypt);
	}

	/**
	 * AES解密AES加密为16进制字符串
	 * @param content 16进制表示形式的加密字节码
	 * @param key
	 * @param charsetName 原文编码方式
	 * @return 原文字符串
	 * @throws Exception
	 */
	public static String AESDecrypt4HexStr(String content, String key, String charsetName) throws Exception {
		byte[] hexDecode = HexDecode(content);
		return AESDecrypt(hexDecode, key, charsetName);
	}

	/**
	 * AES加密为base64字符串
	 * @throws Exception 
	 */
	public static String AESEncrypt2Base64Str(String content, String key, String charsetName) throws Exception {
		try {
			if (key.getBytes().length != 16) {
				throw new Exception("秘钥必须位16位字节");
			}
			byte[] aesEncrypt = AESEncrypt(content.getBytes(charsetName), key.getBytes(), key.getBytes());
			return base64Encode(aesEncrypt);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES解密AES加密为base64的字符串
	 * @param content
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String AESDecrypt4Base64Str(String content, String key, String charsetName) throws Exception {
		try {
			if (key.getBytes().length != 16) {
				throw new Exception("秘钥必须位16位字节");
			}
			byte[] decodeBuffer = base64Decode(content);

			byte[] aesDecryptBytes = AESDecrypt(decodeBuffer, key.getBytes(), key.getBytes());
			return new String(aesDecryptBytes, charsetName);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 封装的base64编码
	 * @param str
	 * @return
	 */
	public static String base64Encode(String str, String charsetName) throws UnsupportedEncodingException {
		try {

			return new BASE64Encoder().encode(str.getBytes(charsetName)).replaceAll("[\\s*\t\n\r]", "");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 封装的base64编码
	 * @param str
	 * @return
	 */
	public static String base64Encode(byte[] bytes) {
		return new BASE64Encoder().encode(bytes).replaceAll("[\\s*\t\n\r]", "");
	}

	/**
	 * 封装的base64解码
	 * @param str
	 * @return
	 */
	public static String base64Decode(String str, String charsetName) throws Exception {
		try {
			return new String(new BASE64Decoder().decodeBuffer(str), charsetName);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw e;
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 封装的base64解码
	 * @param str
	 * @return
	 * @throws IOException 
	 */
	public static byte[] base64Decode(String str) throws IOException {
		return new BASE64Decoder().decodeBuffer(str);
	}

	public static String str2Hex(byte[] b) {
		String hex = "";
		for (int i = 0; i < b.length; i++) {
			hex += Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
		}
		return hex;
	}

	/**
	 * 16进制编码串
	 */
	private static String hexString = "0123456789abcdef";

	/**
	 * 16进制编码
	 * @param str
	 * @param charsetName
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String HexEncode(String str, String charsetName) throws UnsupportedEncodingException {
		//根据默认编码获取字节数组 
		byte[] bytes = str.getBytes(charsetName);
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		//将字节数组中每个字节拆解成2位16进制整数 
		for (int i = 0; i < bytes.length; i++) {
			sb.append(hexString.charAt((bytes[i] & 0xf0) >> 4));
			sb.append(hexString.charAt((bytes[i] & 0x0f) >> 0));
		}
		return sb.toString();
	}

	/**
	 * 16进制解码
	 * @param bytes
	 * @param charsetName
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String HexDecode(String bytes, String charsetName) throws UnsupportedEncodingException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length() / 2);
		//将每2位16进制整数组装成一个字节 
		for (int i = 0; i < bytes.length(); i += 2)
			baos.write((hexString.indexOf(bytes.charAt(i)) << 4 | hexString.indexOf(bytes.charAt(i + 1))));
		return new String(baos.toByteArray(), charsetName);
	}

	/**
	 * 16进制编码
	 * @param bytes
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String HexEncode(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		//将字节数组中每个字节拆解成2位16进制整数 
		for (int i = 0; i < bytes.length; i++) {
			sb.append(hexString.charAt((bytes[i] & 0xf0) >> 4));
			sb.append(hexString.charAt((bytes[i] & 0x0f) >> 0));
		}
		return sb.toString();
	}

	/**
	 * 16进制解码到字节数组
	 * @param bytes
	 * @return
	 */
	public static byte[] HexDecode(String bytes) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length() / 2);
		//将每2位16进制整数组装成一个字节 
		for (int i = 0; i < bytes.length(); i += 2)
			baos.write((hexString.indexOf(bytes.charAt(i)) << 4 | hexString.indexOf(bytes.charAt(i + 1))));
		return baos.toByteArray();
	}

	/**
	 * Created by humf.需要依赖 commons-codec 包 
	 */
	public static class RSAUtil {
		public static final String KEY_ALGORITHM = "RSA";
		public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

		private static final String PUBLIC_KEY = "RSAPublicKey";
		private static final String PRIVATE_KEY = "RSAPrivateKey";

		public static byte[] decryptBASE64(String key) {
			try {
				return base64Decode(key);
			} catch (IOException e) {
				e.printStackTrace();
			}
			return null;
		}

		public static String encryptBASE64(byte[] bytes) {
			return base64Encode(bytes);
		}

		/**
		 * 用私钥对信息生成数字签名
		 *
		 * @param data       加密数据
		 * @param privateKey 私钥
		 * @return
		 * @throws Exception
		 */
		public static String sign(byte[] data, String privateKey) throws Exception {
			// 解密由base64编码的私钥
			byte[] keyBytes = decryptBASE64(privateKey);
			// 构造PKCS8EncodedKeySpec对象
			PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
			// KEY_ALGORITHM 指定的加密算法
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			// 取私钥匙对象
			PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
			// 用私钥对信息生成数字签名
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initSign(priKey);
			signature.update(data);
			return encryptBASE64(signature.sign());
		}

		/**
		 * 校验数字签名
		 *
		 * @param data      加密数据
		 * @param publicKey 公钥
		 * @param sign      数字签名
		 * @return 校验成功返回true 失败返回false
		 * @throws Exception
		 */
		public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
			// 解密由base64编码的公钥
			byte[] keyBytes = decryptBASE64(publicKey);
			// 构造X509EncodedKeySpec对象
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			// KEY_ALGORITHM 指定的加密算法
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			// 取公钥匙对象
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(pubKey);
			signature.update(data);
			// 验证签名是否正常
			return signature.verify(decryptBASE64(sign));
		}

		public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
			// 对密钥解密
			byte[] keyBytes = decryptBASE64(key);
			// 取得私钥
			PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
			// 对数据解密
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		}

		/**
		 * 解密<br>
		 * 用私钥解密
		 *
		 * @param data
		 * @param key
		 * @return
		 * @throws Exception
		 */
		public static byte[] decryptByPrivateKey(String data, String key) throws Exception {
			return decryptByPrivateKey(decryptBASE64(data), key);
		}

		/**
		 * 解密<br>
		 * 用公钥解密
		 *
		 * @param data
		 * @param key
		 * @return
		 * @throws Exception
		 */
		public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
			// 对密钥解密
			byte[] keyBytes = decryptBASE64(key);
			// 取得公钥
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			Key publicKey = keyFactory.generatePublic(x509KeySpec);
			// 对数据解密
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			return cipher.doFinal(data);
		}

		/**
		 * 加密<br>
		 * 用公钥加密
		 *
		 * @param data
		 * @param key
		 * @return
		 * @throws Exception
		 */
		public static byte[] encryptByPublicKey(String data, String key, String charstName) throws Exception {
			// 对公钥解密
			byte[] keyBytes = decryptBASE64(key);
			// 取得公钥
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			Key publicKey = keyFactory.generatePublic(x509KeySpec);
			// 对数据加密
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(data.getBytes(charstName));
		}

		/**
		 * 加密<br>
		 * 用私钥加密
		 *
		 * @param data
		 * @param key
		 * @return
		 * @throws Exception
		 */
		public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
			// 对密钥解密
			byte[] keyBytes = decryptBASE64(key);
			// 取得私钥
			PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
			// 对数据加密
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		}

		/**
		 * 取得私钥
		 *
		 * @param keyMap
		 * @return
		 * @throws Exception
		 */
		public static String getPrivateKey(Map<String, Key> keyMap) throws Exception {
			Key key = (Key) keyMap.get(PRIVATE_KEY);
			return encryptBASE64(key.getEncoded());
		}

		/**
		 * 取得公钥
		 *
		 * @param keyMap
		 * @return
		 * @throws Exception
		 */
		public static String getPublicKey(Map<String, Key> keyMap) throws Exception {
			Key key = keyMap.get(PUBLIC_KEY);
			return encryptBASE64(key.getEncoded());
		}

		/**
		 * 初始化密钥
		 *
		 * @return
		 * @throws Exception
		 */
		public static Map<String, Key> initKey() throws Exception {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGen.initialize(1024);
			KeyPair keyPair = keyPairGen.generateKeyPair();
			Map<String, Key> keyMap = new HashMap(2);
			keyMap.put(PUBLIC_KEY, keyPair.getPublic());// 公钥
			keyMap.put(PRIVATE_KEY, keyPair.getPrivate());// 私钥
			return keyMap;
		}
	}

	/**
	 * 新生成RSA秘钥对
	 */
	public static void createRSATwain() {
		try {
			Map<String, Key> initKey = RSAUtil.initKey();
			String publicKeyNew = RSAUtil.getPublicKey(initKey);
			String privateKeyNew = RSAUtil.getPrivateKey(initKey);
			String str = "新生成的公钥是:" + publicKeyNew + "\r\n"//
					+ "新生成的私钥是:" + privateKeyNew;
			System.out.println(str);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 获取公钥(base64编码字节码)
	 * @return
	 */
	public static String getRSAPublicKey() {
		return publicKey;
	}

	/**
	 * 获取私钥(base64编码字节码)
	 * @return
	 */
	private static String getRSAPrivateKey() {
		return privateKey;
	}

	/**
	 * RSA 公钥加密
	 * @param str
	 * @return base64字节码
	 * @throws Exception 
	 */
	public static String RSAEncrypt(String str) throws Exception {
		byte[] encryptByPublicKey = RSAUtil.encryptByPublicKey(str, publicKey, "UTF-8");
		String encode = base64Encode(encryptByPublicKey);
		return encode;
	}

	/**
	 * RSA 私钥解密
	 * @param str base64字节码
	 * @return UTF-8编码
	 */
	public static String RSADecrypt(String str) throws Exception {
		byte[] decryptByPrivateKey = RSAUtil.decryptByPrivateKey(str, privateKey);
		return new String(decryptByPrivateKey, "UTF-8");
	}

	/**
	 * 获取MD5加密
	 * @param pwd 需要加密的字符串
	 * @return String 字符串 加密后的字符串
	 */
	public static String md5To32DownForUTF8(String pwd) {
		try {
			// 创建加密对象
			MessageDigest digest = MessageDigest.getInstance("md5");

			// 调用加密对象的方法，加密的动作已经完成
			byte[] bs = digest.digest(pwd.getBytes("UTF-8"));
			// 接下来，我们要对加密后的结果，进行优化，按照mysql的优化思路走
			// mysql的优化思路：
			// 第一步，将数据全部转换成正数：
			String hexString = "";
			for (byte b : bs) {
				// 第一步，将数据全部转换成正数：
				// 解释：为什么采用b&255
				/*
				 * b:它本来是一个byte类型的数据(1个字节) 255：是一个int类型的数据(4个字节)
				 * byte类型的数据与int类型的数据进行运算，会自动类型提升为int类型 eg: b: 1001 1100(原始数据)
				 * 运算时： b: 0000 0000 0000 0000 0000 0000 1001 1100 255: 0000
				 * 0000 0000 0000 0000 0000 1111 1111 结果：0000 0000 0000 0000
				 * 0000 0000 1001 1100 此时的temp是一个int类型的整数
				 */
				int temp = b & 255;
				// 第二步，将所有的数据转换成16进制的形式
				// 注意：转换的时候注意if正数>=0&&<16，那么如果使用Integer.toHexString()，可能会造成缺少位数
				// 因此，需要对temp进行判断
				if (temp < 16 && temp >= 0) {
					// 手动补上一个“0”
					hexString = hexString + "0" + Integer.toHexString(temp);
				} else {
					hexString = hexString + Integer.toHexString(temp);
				}
			}
			return hexString;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}

	/**
	 * md5加密
	 * @param str
	 * @return
	 */
	public static String md5(String str) {
		return md5To32DownForUTF8(str);
	}

	/**
	 * md5加密
	 * @param str
	 * @return
	 */
	public static String md5(String... str) {
		String s = "";
		for (int i = 0; i < str.length; i++) {
			s += str[i];
		}
		return md5(s);
	}

	public static String getSimpleJson(String... str) {
		String returnStr = "";
		returnStr += "{";
		for (int i = 0; i < str.length; i += 2) {
			if (i == (str.length - 2)) {
				returnStr += "\"";
				returnStr += str[i];
				returnStr += "\"";
				returnStr += ":";
				returnStr += "\"";
				returnStr += str[i + 1];
				returnStr += "\"";
			} else {
				returnStr += "\"";
				returnStr += str[i];
				returnStr += "\"";
				returnStr += ":";
				returnStr += "\"";
				returnStr += str[i + 1];
				returnStr += "\"";
				returnStr += ",";
			}
		}
		returnStr += "}";
		return returnStr;
	}

	/**
	 * ToString
	 */
	public static <T> void toString(T t) {
		try {
			String str = "";
			Field[] declaredFields = t.getClass().getDeclaredFields();
			str += t.getClass().getName() + " [";
			for (int i = 0; i < declaredFields.length; i++) {
				declaredFields[i].setAccessible(true);
				if (i != declaredFields.length - 1) {
					str += declaredFields[i].getName();
					str += ":";
					str += declaredFields[i].get(t);
					str += ", ";
				} else {
					str += declaredFields[i].getName();
					str += ":";
					str += declaredFields[i].get(t);
				}
			}
			str += "]";
			System.out.println(str);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 用户状态信息
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface userState {
	}

	/**
	 * 用户状态签名
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface userStateSign {
	}

	/**
	 * AESKey
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface AESKey {
	}

	/**
	 * 根据用户状态 生成用户状态指纹
	 * @param t
	 * @return
	 * @throws Exception
	 */
	public static <T> void createUserStateSign(T t) throws Exception {
		ArrayList<String> list = new ArrayList<String>();
		Field[] fields = t.getClass().getDeclaredFields();
		Field signField = null;
		for (Field field : fields) {
			field.setAccessible(true);
			if (field.isAnnotationPresent(WWUtils.userState.class)) {
				list.add((String) field.get(t));
			}
			if (field.isAnnotationPresent(WWUtils.userStateSign.class)) {
				signField = field;
			}
		}
		list.add(WWUtils.PROJECT_KEY);
		String[] array = list.toArray(new String[list.size()]);
		if (WWUtils.isBlank(array)) {
			throw new Exception("状态字段为空");
		}
		signField.set(t, WWUtils.md5(array));
	}

	/**
	 * 验证用户状态
	 * @throws IllegalAccessException 
	 * @throws IllegalArgumentException 
	 */
	public static <T> boolean checkUserStateSign(T t) throws Exception {
		//获取用户状态信息
		ArrayList<String> list = new ArrayList<String>();
		Field[] fields = t.getClass().getDeclaredFields();
		//获取用户状态指纹
		Field signField = null;
		for (Field field : fields) {
			field.setAccessible(true);
			if (field.isAnnotationPresent(WWUtils.userState.class)) {
				list.add((String) field.get(t));
			}
			if (field.isAnnotationPresent(WWUtils.userStateSign.class)) {
				signField = field;
			}
		}
		list.add(WWUtils.PROJECT_KEY);
		String[] array = (String[]) list.toArray(new String[list.size()]);
		if (WWUtils.isBlank(array)) {
			throw new Exception("状态字段为空");
		}
		String sign = (String) signField.get(t);
		if (WWUtils.isBlank(sign)) {
			return false;
		}
		if (WWUtils.md5(array).equals(sign)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * uri编码字段
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface URICode {
	}

	/**
	 * URI解码全部URICode字段
	 * @throws Exception
	 */
	public static <T> void URIdecodeAllField(T t) throws Exception {
		Field[] declaredFields = t.getClass().getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.URICode.class)) {
					String fieldData = (String) field.get(t);
					if (fieldData != null && !WWUtils.isBlank(fieldData)) {
						field.set(t, WWUtils.URIDecode(fieldData, "UTF-8"));
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * URI编码全部字段
	 * @throws Exception
	 */
	public static <T> void URIencodeAllField(T t) throws Exception {
		Field[] declaredFields = t.getClass().getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.URICode.class)) {
					String fieldData = (String) field.get(t);
					if (fieldData != null && !WWUtils.isBlank(fieldData)) {
						field.set(t, WWUtils.URIEncode(fieldData, "UTF-8"));
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * RSA加密AESKey
	 */
	public static <T> void RSAEncryptAESKey(T t) throws Exception {
		Field[] declaredFields = t.getClass().getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.AESKey.class)) {
					field.set(t, WWUtils.RSAEncrypt((String) field.get(t)));
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}

	}

	/**
	 * RSA解密AESKey
	 */
	public static <T> void RSADecryptAESKey(T t) throws Exception {
		Field[] declaredFields = t.getClass().getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.AESKey.class)) {
					field.set(t, WWUtils.RSADecrypt((String) field.get(t)));
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}

	}

	/**
	 * 获取对象AESKey注解字段的值
	 * @param t
	 * @return
	 * @throws Exception
	 */
	public static <T> String getAESKey(T t) throws Exception {
		Field[] fields = t.getClass().getDeclaredFields();
		try {
			for (Field field : fields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.AESKey.class)) {
					return (String) field.get(t);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		throw new Exception("没有AESKey注解标识的字段");
	}

	/**
	 * AES解密全部字段(排除AES字段本身)
	 * @throws Exception
	 */
	public static <T> void AESdecryptAllField(T t) throws Exception {
		String AESkey = WWUtils.getAESKey(t);
		Field[] declaredFields = t.getClass().getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				String fieldData = (String) field.get(t);
				if (fieldData != null && !WWUtils.isBlank(fieldData)) {
					if (!field.isAnnotationPresent(WWUtils.AESKey.class)) {
						field.set(t, WWUtils.AESDecrypt4Base64Str(fieldData, AESkey, "UTF-8"));
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * AES加密全部字段(排除AES字段本身)
	 * @throws Exception
	 */
	public static <T> void AESencryptAllField(T t) throws Exception {
		String AESkey = WWUtils.getAESKey(t);
		Field[] declaredFields = t.getClass().getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				String fieldData = (String) field.get(t);
				if (fieldData != null && !WWUtils.isBlank(fieldData)) {
					if (!field.isAnnotationPresent(WWUtils.AESKey.class)) {
						field.set(t, WWUtils.AESEncrypt2Base64Str(fieldData, AESkey, "UTF-8"));
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 去除特殊符号
	 */
	public static String describe(String str) {
		return Matcher("[\u4e00-\u9fa5]|[0123456789]|[a-z]|[A-Z]", str);
	}

	/**
	 * 描述标识(去除特殊符号用)
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface Describe {
		/**
		 * 对应字段名
		 */
		String value();
	}

	/**
	 * 设置所有描述字段为标识的字段的描述信息
	 * @param t
	 * @throws Exception
	 */
	public static <T> void describeAll(T t) throws Exception {
		Class<? extends Object> classT = t.getClass();
		Field[] declaredFields = classT.getDeclaredFields();
		try {
			for (Field field : declaredFields) {
				field.setAccessible(true);
				if (field.isAnnotationPresent(WWUtils.Describe.class)) {
					Object fieldData = field.get(t);
					if (fieldData == null || WWUtils.isBlank((String) fieldData)) {
						//如果当前字段为空 跳过
						continue;
					}
					//获取目标字段名
					String targetColname = field.getAnnotation(WWUtils.Describe.class).value();
					//获取目标字段
					Field targetField = classT.getDeclaredField(targetColname);
					//设置目标字段可访问
					targetField.setAccessible(true);
					//获取目标字段将要设置的数据
					String targetString = (String) fieldData;
					//设置目标数据
					targetField.set(t, describe(targetString));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * sign验证字段
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface SignParam {
	}

	/**
	 * sign验证字段
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface Sign {
	}

	/**
	 * 根据SignParam注解(非空)字段,验证sign
	 * @param t
	 * @return
	 * @throws IllegalAccessException 
	 * @throws IllegalArgumentException 
	 */
	public static <T> boolean checkSign(T t) throws Exception {
		//封装的SignParam数据
		Map<String, String> map = new TreeMap<String, String>();
		//封装要验证的sign
		String sign = "";
		Field[] fields = t.getClass().getDeclaredFields();
		for (Field field : fields) {
			field.setAccessible(true);
			Object object = field.get(t);
			if (object == null || isBlank((String) object)) {
				//为空不处理
				continue;
			}
			if (field.isAnnotationPresent(WWUtils.SignParam.class)) {
				//有SignParam注解添加到map中
				map.put(field.getName(), (String) field.get(t));
			}
			if (field.isAnnotationPresent(WWUtils.Sign.class)) {
				sign = (String) field.get(t);
			}
		}

		return checkSign(map, sign);
	}

	/**
	 * 根据SignParam注解(非空)字段,验证sign
	 * @param t
	 * @return
	 * @throws IllegalAccessException 
	 * @throws IllegalArgumentException 
	 */
	public static <T> boolean checkSign(T t, String key) throws Exception {
		//封装的SignParam数据
		Map<String, String> map = new TreeMap<String, String>();
		//封装要验证的sign
		String sign = "";
		Field[] fields = t.getClass().getDeclaredFields();
		for (Field field : fields) {
			field.setAccessible(true);
			Object object = field.get(t);
			if (object == null || isBlank((String) object)) {
				//为空不处理
				continue;
			}
			if (field.isAnnotationPresent(WWUtils.SignParam.class)) {
				//有SignParam注解添加到map中
				map.put(field.getName(), (String) field.get(t));
			}
			if (field.isAnnotationPresent(WWUtils.Sign.class)) {
				sign = (String) field.get(t);
			}
		}

		return checkSign(map, sign, key);
	}

	/**
	 * 验证sign
	 * @param map
	 * @param sign
	 */
	public static boolean checkSign(Map<String, String> map, String sign) {
		String str = createSignStr4Map(map);
		return md5(str).equals(sign);
	}

	/**
	 * 验证sign
	 * @param map
	 * @param sign
	 */
	public static boolean checkSign(Map<String, String> map, String sign, String apiKey) {
		String str = createSignStr4Map(map) + "&key=" + apiKey;
		return md5(str).equals(sign);
	}

	/**
	 * 根据map生成要加密的串
	 * @param map
	 */
	private static String createSignStr4Map(Map<String, String> map) {
		String returnStr = "";
		String[] keyValues = map.keySet().toArray(new String[map.size()]);
		for (int i = 0; i < map.size(); i++) {
			if (i != map.size() - 1) {
				returnStr += keyValues[i] + "=" + map.get(keyValues[i]) + "&";
			} else {
				returnStr += keyValues[i] + "=" + map.get(keyValues[i]) + "";
			}
		}
		return returnStr;
	}

	/**
	 * 表明
	 */
	@Target({ ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface DbTableName {
		/**
		 * 表名
		 * @return
		 */
		String value();
	}

	/**
	 * 生成简单insert sql 
	 * @throws IllegalAccessException 
	 * @throws IllegalArgumentException 
	 */
	public static <T> String createSimpleInsertSql(T t) throws Exception {
		Class<? extends Object> classT = t.getClass();
		String tableName = classT.getAnnotation(WWUtils.DbTableName.class).value();
		String sql = "INSERT INTO " + tableName + "(";
		String keys = "";
		String values = "";
		Field[] fields = classT.getDeclaredFields();
		for (Field field : fields) {
			field.setAccessible(true);
			Object object = field.get(t);
			if (object == null || isBlank((String) object)) {
				//为空不处理
				continue;
			}
			if (field.isAnnotationPresent(WWUtils.DbColumn.class)) {
				//是数据库字段
				keys += field.getAnnotation(WWUtils.DbColumn.class).value() + ",";
				values += "'" + (String) field.get(t) + "'" + ",";
			}
		}
		sql += keys.substring(0, keys.length() - 1);
		sql += ")" + " VALUES(";
		sql += values.substring(0, values.length() - 1);
		sql += ");";
		return sql;
	}

	/**
	 * id字段
	 */
	@Target({ ElementType.FIELD })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface DbID {
	}

	/**
	 * 生成简单update sql
	 * @param t
	 * @return
	 * @throws Exception
	 */
	public static <T> String createSimpleUpdateSql(T t) throws Exception {
		Class<? extends Object> classT = t.getClass();
		String tableName = classT.getAnnotation(WWUtils.DbTableName.class).value();
		String sql = "UPDATE " + tableName + " SET ";
		Field[] fields = classT.getDeclaredFields();
		String idColunmName = "";
		String idValue = "";
		for (Field field : fields) {
			field.setAccessible(true);
			Object object = field.get(t);
			if (object == null || isBlank((String) object)) {
				//为空不处理
				continue;
			}
			if (field.isAnnotationPresent(WWUtils.DbColumn.class)) {
				if (field.isAnnotationPresent(WWUtils.DbID.class)) {
					//是id字段
					idColunmName = field.getAnnotation(WWUtils.DbColumn.class).value();
					idValue = (String) field.get(t);
				} else {
					//是数据库字段(非id字段)
					sql += field.getAnnotation(WWUtils.DbColumn.class).value();
					sql += " = ";
					sql += "'" + (String) field.get(t) + "'";
					sql += ",";
				}
			}
		}
		sql = sql.substring(0, sql.length() - 1);
		sql += " WHERE " + idColunmName + " = " + "'" + idValue + "'" + ";";
		return sql;
	}

	/**
	 * 生成随机数
	 * @param str 随机数
	 */
	public static String randomNumber(String str, int count) {
		StringBuffer sb = new StringBuffer();
		Random r = new Random();
		for (int i = 0; i < count; i++) {
			int num = r.nextInt(str.length());
			sb.append(str.charAt(num));
			str = str.replace((str.charAt(num) + ""), "");
		}
		return sb.toString();
	}

	/**
	 * 生成随机fID
	 * @return
	 */
	public static String randomFID() {
		return Long.toString(System.currentTimeMillis()) + randomNumber("0123456789", 10);
	}

	/**
	 * 封装查询到的数据到对象
	 * @param rs
	 * @param clazz
	 * @return
	 * @throws Exception 
	 */
	@Deprecated
	public static <T> List<T> getListObj4DbRs(ResultSet rs, Class<T> clazz) throws Exception {
		ResultSetMetaData metaData = rs.getMetaData();
		int columnCount = metaData.getColumnCount();
		//所有列名
		String[] dbColumnNames = new String[columnCount];
		List<String> dbColumnNameList = Arrays.asList(dbColumnNames);
		for (int i = 0; i < columnCount; i++) {
			dbColumnNames[i] = metaData.getColumnName(i + 1);
		}

		//获取类对应的列名<查询字段名,对应列名>
		Map<String, Field> fieldMap = new HashMap<String, Field>();
		for (Field field : clazz.getDeclaredFields()) {
			field.setAccessible(true);
			//判断是否是数据库映射字段
			if (field.isAnnotationPresent(WWUtils.DbColumn.class)) {
				String annotationValue = field.getAnnotation(WWUtils.DbColumn.class).value();
				//判断是否是查询中存在的数据
				if (dbColumnNameList.contains(annotationValue)) {
					fieldMap.put(annotationValue, field);
				}
			}
		}

		List<T> list = new ArrayList<T>();
		while (rs.next()) {
			T t = clazz.newInstance();
			Set<String> keySet = fieldMap.keySet();
			for (String dbColumnName : keySet) {
				String stringValue = rs.getString(dbColumnName);
				Field field = fieldMap.get(dbColumnName);
				field.set(t, stringValue);
			}
			list.add(t);
		}

		return list;
	}

	/**
	 * URI标识列(非空)到json对象字符串
	 * @param t
	 * @return
	 * @throws IllegalAccessException 
	 * @throws IllegalArgumentException 
	 */
	public static <T> String toJsonString(T t) throws Exception {
		String str = "{";
		Field[] declaredFields = t.getClass().getDeclaredFields();
		for (Field field : declaredFields) {
			field.setAccessible(true);
			Object fieldData = field.get(t);
			if (fieldData == null || WWUtils.isBlank((String) fieldData)) {
				continue;
			}
			if (field.isAnnotationPresent(WWUtils.URICode.class)) {
				//是URI可编码的
				String colunmName = field.getName();
				String colunmValue = (String) field.get(t);
				str += "\"";
				str += colunmName;
				str += "\"";
				str += ":";
				str += "\"";
				str += colunmValue;
				str += "\"";
				str += ",";
			}
		}
		if(str.length()!=1){
			str = str.substring(0, str.length() - 1);
		}
		str += "}";
		return str;
	}

	/**
	 * json字符串
	 * @param state
	 * @param message
	 * @return
	 */
	public static String getJsonFmt(String state, String message) {

		StackTraceElement stack[] = Thread.currentThread().getStackTrace();
		String className = stack[2].getClassName();
		String methodName = stack[2].getMethodName();
		int lineNumber = stack[2].getLineNumber();
		String s = "{\"state\":\"" + state + "\",\"message\":\"" + message + "\"}";
		System.out.println("[返回]className:[" + className + "] methodName:[" + methodName + "][" + lineNumber + "]" + s);
		return s;
	}

	/**
	 * json字符串
	 * @param state
	 * @param message
	 * @param data
	 * @return
	 */
	public static String getJsonFmt(String state, String message, String data) {
		StackTraceElement stack[] = Thread.currentThread().getStackTrace();
		String className = stack[2].getClassName();
		String methodName = stack[2].getMethodName();
		int lineNumber = stack[2].getLineNumber();
		String s = "{\"state\":\"" + state + "\",\"message\":\"" + message + "\", " + data + "}";
		System.out.println("[返回]className:[" + className + "] methodName:[" + methodName + "][" + lineNumber + "]" + s);
		return s;
	}

	/**
	 * json字符串
	 * @param data
	 * @param name
	 * @param value
	 * @return
	 */
	public static String setJsonFmt(String data, String name, String value) {
		name = name.trim();
		if (data.equals(""))
			return data = "\"" + name + "\":\"" + value + "\"";
		else
			return data = data + ",\"" + name + "\":\"" + value + "\"";
	}

	public static void main(String[] args) throws Exception {
		System.out.println(WWUtils.URIEncode("01", "UTF-8"));
	}

}
