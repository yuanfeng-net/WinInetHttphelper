using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace WinInetHelper
{
    public class ResponseModel
    {
        /// <summary>
        /// 返回的Html文本
        /// </summary>
        public string Html { get; set; }
        /// <summary>
        /// 返回的Cookie
        /// </summary>
        public string Cookie { get; set; }
        /// <summary>
        /// 返回的字节集
        /// </summary>
        public byte[] ByteArr { get; set; }
        /// <summary>
        /// 返回的协议头文本
        /// </summary>
        public string Header { get; set; }

        public string Location { get; set; }

        /// <summary>
        /// 返回的协议头字典集合
        /// </summary>
        public Dictionary<string, string> DicHeader { get; set; }
    }


    public class WinInetClass
    {
        #region Dll封装

        [DllImport("wininet.dll", EntryPoint = "InternetSetOptionA", CharSet = CharSet.Ansi, SetLastError = true, PreserveSig = true)]
        public static extern bool InternetSetOption(int hInternet, int dwOption, ref int lpBuffer, int dwBufferLength);

        /// <summary>
        /// Internet激活
        /// </summary>
        /// <param name="handelName">句柄名称</param>
        /// <param name="connectionType">连接类型  1直接连接;3代理连接</param>
        /// <param name="sProxyName">代理地址</param>
        /// <param name="sProxyBypass">代理掩码</param>
        /// <param name="lFlags">dwFlags</param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "InternetOpenA")]
        static extern int InternetOpenA(string handelName, int connectionType, string sProxyName, string sProxyBypass, int lFlags);

        /// <summary>
        /// Internet建立连接
        /// </summary>
        /// <param name="ieHandel"></param>
        /// <param name="lpszServerName"></param>
        /// <param name="nServerPort">80HTTP;21FTP;</param>
        /// <param name="lpszUsername"></param>
        /// <param name="lpszPassword"></param>
        /// <param name="dwService">1FTP;3HTTP</param>
        /// <param name="dwFlags">0http;134217728被动FTP模式</param>
        /// <param name="dwContext"></param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "InternetConnectA")]
        static extern int InternetConnectA(int ieHandel, string lpszServerName, int nServerPort, string lpszUsername, string lpszPassword, int dwService, int dwFlags, int dwContext);

        /// <summary>
        /// Internet关闭句柄
        /// </summary>
        /// <param name="handel">句柄</param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "InternetCloseHandle")]
        static extern bool InternetCloseHandle(int handel);

        /// <summary>
        /// HTTP查询信息
        /// </summary>
        /// <param name="requestHandel"></param>
        /// <param name="dwInfoLevel">22返回所有信息;43SET_COOKIE;+2147483648返回文本</param>
        /// <param name="lpBuffer"></param>
        /// <param name="lpBufferLength"></param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "HttpQueryInfoA", ExactSpelling = true, CharSet = CharSet.Ansi, SetLastError = true)]
        static extern bool HttpQueryInfo(IntPtr hHttpRequest, int lInfoLevel, byte[] sBuffer, ref int lBufferLength, int lIndex);

        /// <summary>
        /// Internet读文件
        /// </summary>
        /// <param name="requestHandel"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="lNumBytesToRead"></param>
        /// <param name="lNumberOfBytesRead"></param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "InternetReadFile")]
        static extern bool InternetReadFile(int requestHandel, byte[] lpBuffer, int lNumBytesToRead, out int lNumberOfBytesRead);

        /// <summary>
        /// Http创建请求
        /// </summary>
        /// <param name="requestHandel">由Internet建立连接返回</param>
        /// <param name="lpszVerb">"GET" or "POST"为空默认GET</param>
        /// <param name="lpszObjectName">简短路径,不带域名</param>
        /// <param name="lpszVersion">为空默认HTTP/1.1</param>
        /// <param name="lpszReferer">可为空</param>
        /// <param name="lplpszAcceptTypes">可为空</param>
        /// <param name="dwFlags">2147483648更新下载</param>
        /// <param name="dwContext">0</param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "HttpOpenRequestA")]
        static extern int HttpOpenRequestA(int requestHandel, string lpszVerb, string lpszObjectName, string lpszVersion, string lpszReferer, string lplpszAcceptTypes, int dwFlags, int dwContext);

        /// <summary>
        /// Http发送请求
        /// </summary>
        /// <param name="requestHandel">HTTP请求句柄</param>
        /// <param name="lpszHeaders">附加协议头</param>
        /// <param name="dwHeadersLength">附加协议头长度</param>
        /// <param name="lpOptional">提交信息</param>
        /// <param name="dwOptionalLength">提交信息长度</param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "HttpSendRequestA")]
        static extern bool HttpSendRequestA(int requestHandel, string lpszHeaders, int dwHeadersLength, string lpOptional, int dwOptionalLength);

        /// <summary>
        /// Http发送请求
        /// </summary>
        /// <param name="requestHandel">HTTP请求句柄</param>
        /// <param name="lpszHeaders">附加协议头</param>
        /// <param name="dwHeadersLength">附加协议头长度</param>
        /// <param name="lpOptional">提交信息</param>
        /// <param name="dwOptionalLength">提交信息长度</param>
        /// <returns></returns>
        [DllImport("wininet.dll", EntryPoint = "HttpSendRequestA")]
        static extern bool HttpSendRequestAByBytes(int requestHandel, string lpszHeaders, int dwHeadersLength, byte[] lpOptional, int dwOptionalLength);

        [DllImport("wininet.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, StringBuilder pchCookieData, ref uint pcchCookieData, int dwFlags, IntPtr lpReserved);

        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="timeout">设置超时时间</param>
        public WinInetClass(int timeout=20)
        {
            WininetTimeOut = timeout;
        }

        public void AddHead(string key, string value)
        {
            if (!ContentHeads.ContainsKey(key))
            {
                ContentHeads.Add(key, value);
            }
            else
            {
                ContentHeads[key] = value;
            }
        }


        public void RemoveHead(string key)
        {
            if (ContentHeads.ContainsKey(key))
            {
                ContentHeads.Remove(key);
            }
        }


        public void AddOneTimeHead(string key, string value)
        {
            if (!OneTimeContentHeads.ContainsKey(key))
            {
                OneTimeContentHeads.Add(key, value);
            }
            else
            {
                OneTimeContentHeads[key] = value;
            }
        }

        private Dictionary<string, string> ContentHeads = new Dictionary<string, string>();

        private Dictionary<string, string> OneTimeContentHeads = new Dictionary<string, string>();

        string user_Agent = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)";

        public void SetUserAgent(string userAgent)
        {
            user_Agent = userAgent;
        }

        private int WininetTimeOut = 10;
        /// <summary>
        /// 全局代理IP
        /// </summary>
        public string ServerPort { get; set; }

        #region 方法重载
        /// <summary>
        /// Get方式访问带cookie
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="cookie">请求cookie</param>
        /// <param name="refurl">refurl</param>
        /// <returns></returns>
        public ResponseModel GetHtml(string url, string cookie, string refurl = "")
        {
            return GetHtml(url, HttpType.Get, "", null, cookie, refurl);
        }
        /// <summary>
        /// Get方式访问指定是否重定向
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="isautoredirect">是否重定向</param>
        /// <returns></returns>
        public ResponseModel GetHtml(string url, bool isautoredirect)
        {
            return GetHtml(url, HttpType.Get, "", null, "", url, "", isautoredirect);
        }
        /// <summary>
        /// Get方式访问
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="cookie">cookie</param>
        /// <param name="isautoredirect">是否重定向</param>
        /// <returns></returns>
        public ResponseModel GetHtml(string url, string cookie, bool isautoredirect)
        {
            return GetHtml(url, HttpType.Get, "", null, cookie, url, "", isautoredirect);
        }
        /// <summary>
        /// Post方式访问
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="postData">请求数据</param>
        /// <param name="cookie">cookie不传则使用自动处理的cookie</param>
        /// <param name="refurl">refurl不传则使用url</param>
        /// <param name="isautoredirect">是否重定向不传则默认禁止</param>
        /// <returns></returns>
        public ResponseModel PostHtml(string url, string postData, string cookie = "", string refurl = "", bool isautoredirect = false)
        {
            return GetHtml(url, HttpType.Post, postData, null, cookie, refurl, "", isautoredirect);
        }
        /// <summary>
        /// Post方式访问
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="postData">请求数据 字节集</param>
        /// <param name="cookie"></param>
        /// <param name="refurl"></param>
        /// <param name="isautoredirect"></param>
        /// <returns></returns>
        public ResponseModel PostHtml(string url, byte[] postData, string cookie = "", string refurl = "", bool isautoredirect = false)
        {
            return GetHtml(url, HttpType.Post, "", postData, cookie, refurl, "", isautoredirect);
        }
        /// <summary>
        /// Post方式访问
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="postData">请求数据</param>
        /// <param name="isautoredirect">是否重定向</param>
        /// <returns></returns>
        public ResponseModel PostHtml(string url, string postData, bool isautoredirect = false)
        {
            return GetHtml(url, HttpType.Post, postData, null, "", url, "", isautoredirect);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="url">请求地址</param>
        /// <param name="postData">请求数据 字节集</param>
        /// <param name="isautoredirect">是否重定向</param>
        /// <returns></returns>
        public ResponseModel PostHtml(string url, byte[] postData, bool isautoredirect = false)
        {
            return GetHtml(url, HttpType.Post, "", postData, "", url, "", isautoredirect);
        }

        #endregion

        #region 主方法

        public ResponseModel GetHtml(string url, HttpType type = HttpType.Get, string postData = "", byte[] postBytes = null, string cookie = null, string refurl = "", string serverPort = "", bool isautoredirect = false)
        {
            ResponseModel model = new ResponseModel();
            //定义句柄变量
            int internetHandel=0, internetConnectionHandel=0, inernetOpenHandel = 0;

            int lngCTimeOut = WininetTimeOut * 1000;
            int lngRTimeOut = WininetTimeOut * 1000;
            bool lnghOption = false;

            try
            {
                //设置代理
                if (string.IsNullOrEmpty(serverPort) && !string.IsNullOrEmpty(ServerPort))
                {
                    serverPort = ServerPort;
                }

                Uri uri = new Uri(url);

                //请求方式
                string typeStr = type == HttpType.Get ? "GET" : "POST";
                //是否是https请求
                bool isHttps = url.ToLower().StartsWith("https");

                if (string.IsNullOrEmpty(serverPort))
                {
                    internetHandel = InternetOpenA(user_Agent, 1, string.Empty, string.Empty, 0);
                }
                else
                {
                    //处理代理地址
                    if (isHttps)
                    {
                        internetHandel = InternetOpenA(user_Agent, 3, serverPort, string.Empty, 0);
                    }
                    else
                    {
                        internetHandel = InternetOpenA(user_Agent, 3, "http=" + serverPort, string.Empty, 0);
                    }
                }

                if (internetHandel <= 0)
                {
                    InternetCloseHandle(internetHandel);
                    return null;
                }


                //连接超时时间设定  
                lnghOption = InternetSetOption(internetHandel, 2, ref lngCTimeOut, Marshal.SizeOf(lngCTimeOut));

                lnghOption = InternetSetOption(internetHandel, 6, ref lngRTimeOut, Marshal.SizeOf(lngRTimeOut));

                //取连接句柄
                internetConnectionHandel = InternetConnectA(internetHandel, uri.DnsSafeHost, uri.Port, string.Empty, string.Empty, 3, 0, 0);

                if (internetConnectionHandel <= 0)
                {
                    InternetCloseHandle(internetConnectionHandel);
                    InternetCloseHandle(internetHandel);
                    return null;
                }

                int dwFlags = -2147483632;

                if (cookie != null)
                {
                    dwFlags = dwFlags | 524288;//INTERNET_FLAG_NO_COOKIES
                }

                //禁止重定向
                if (!isautoredirect)
                {
                    dwFlags = dwFlags | 2097152;//INTERNET_FLAG_NO_COOKIES
                }

                //检测是否是https请求
                if (isHttps)
                {
                    dwFlags = dwFlags | 8388608;
                }
                else
                {
                    dwFlags = dwFlags | 16384;
                }

                inernetOpenHandel = HttpOpenRequestA(internetConnectionHandel, typeStr, uri.PathAndQuery, "HTTP/1.1", string.Empty, string.Empty, dwFlags, 0);
                if (inernetOpenHandel <= 0)
                {
                    InternetCloseHandle(inernetOpenHandel);
                    InternetCloseHandle(internetConnectionHandel);
                    InternetCloseHandle(internetHandel);
                    return null;
                }
                if (string.IsNullOrEmpty(refurl))
                {
                    refurl = url;
                }
                string lpszHeaders = string.Empty;
                StringBuilder sbHeader = new StringBuilder();



                if (!ContentHeads.ContainsKey("Accept") && !OneTimeContentHeads.ContainsKey("Accept"))
                {
                    sbHeader.AppendLine("Accept: application/json,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
                }
                if (!ContentHeads.ContainsKey("Referer") && !OneTimeContentHeads.ContainsKey("Referer"))
                {
                    sbHeader.AppendLine("Referer: " + refurl);
                }
                if (!ContentHeads.ContainsKey("Accept-Language") && !OneTimeContentHeads.ContainsKey("Accept-Language"))
                {
                    sbHeader.AppendLine("Accept-Language: zh-cn");
                }
                if (!ContentHeads.ContainsKey("Content-Type") && !OneTimeContentHeads.ContainsKey("Content-Type"))
                {
                    if (type == HttpType.Post)
                    {
                        sbHeader.AppendLine("Content-Type: application/x-www-form-urlencoded");
                    }
                }

                if (!string.IsNullOrEmpty(cookie) && !ContentHeads.ContainsKey("Cookie") && !OneTimeContentHeads.ContainsKey("Cookie"))
                {
                    sbHeader.AppendLine("Cookie: " + cookie);
                }

                foreach (var kv in ContentHeads)
                {
                    if (OneTimeContentHeads.ContainsKey(kv.Key))
                    {
                        sbHeader.AppendLine(kv.Key + ": " + OneTimeContentHeads[kv.Key]);
                        OneTimeContentHeads.Remove(kv.Key);
                    }
                    else
                    {
                        sbHeader.AppendLine(kv.Key + ": " + kv.Value);
                    }
                }

                foreach (var kv in OneTimeContentHeads)
                {
                    sbHeader.AppendLine(kv.Key + ": " + kv.Value);
                }

                lpszHeaders = sbHeader.ToString();

                //连接超时时间设定  
                lnghOption = InternetSetOption(inernetOpenHandel, 2, ref lngCTimeOut, Marshal.SizeOf(lngCTimeOut));

                lnghOption = InternetSetOption(inernetOpenHandel, 6, ref lngRTimeOut, Marshal.SizeOf(lngRTimeOut));


                //提交请求
                if (type == HttpType.Get)
                {

                    HttpSendRequestA(inernetOpenHandel, lpszHeaders, lpszHeaders.Length, string.Empty, 0);

                }
                else
                {
                    if (postBytes == null)
                    {
                        postBytes = Encoding.UTF8.GetBytes(postData);
                    }

                    HttpSendRequestAByBytes(inernetOpenHandel, lpszHeaders, lpszHeaders.Length, postBytes, postBytes.Length);
                }


                byte[] retHeader = new byte[5000];
                int maxHeaderLength = retHeader.Length;
                //获取返回协议头
                HttpQueryInfo((IntPtr)inernetOpenHandel, 22, retHeader, ref maxHeaderLength, 0);

                Dictionary<string, string> dicHeaders = new Dictionary<string, string>();

                //分析返回协议头
                string rh = Encoding.Default.GetString(retHeader);

                string[] headerArr = rh.Split(new string[] { System.Environment.NewLine, "\r\n" }, StringSplitOptions.None);
                StringBuilder sbCookie = new StringBuilder();
                headerArr.ToList().ForEach((e) =>
                {
                    string[] arr = e.Split(':');
                    if (arr.Length > 1)
                    {
                        string name = arr[0].ToLower();
                        string value = arr[1];
                        if (arr.Length > 2)
                        {
                            value = e.Remove(0, name.Length + 1);
                        }

                        //清除cookie冗余信息
                        if (name == "set-cookie")
                        {
                            value = ClearCookie(value);

                        }

                        if (dicHeaders.ContainsKey(name))
                        {
                            dicHeaders[name] += value;
                        }
                        else
                        {
                            dicHeaders.Add(name, value);
                        }
                    }
                });

                if (dicHeaders.ContainsKey("set-cookie"))
                {
                    model.Cookie = dicHeaders["set-cookie"];
                }

                if (dicHeaders.ContainsKey("location"))
                {
                    model.Location = dicHeaders["location"].Trim();
                }

                //为model赋值协议头
                model.Header = rh;
                model.DicHeader = dicHeaders;
                //Content-Type: text/html;charset=GBK
                //   Encoding encoding = ;
                string ec = "utf-8";
                if (dicHeaders.ContainsKey("content-type"))
                {
                    ec = dicHeaders["content-type"] + "||";
                }

                ec = Regex.Match(ec, "charset=(?<深秋术师>(.*?))\\|\\|").Groups["深秋术师"].Value;//by 深秋术师

                if (string.IsNullOrEmpty(ec))
                    ec = "utf-8";

                Encoding encoding = Encoding.UTF8;
                try
                {
                    encoding = Encoding.GetEncoding(ec);
                }
                catch
                {

                }

                int runCount = 0;
                byte[] requestBytes = new byte[1024];
                using (MemoryStream rstream = new MemoryStream())
                {
                    do
                    {
                        InternetReadFile(inernetOpenHandel, requestBytes, requestBytes.Length, out runCount);
                        rstream.Write(requestBytes, 0, runCount);

                    } while (runCount != 0);

                    rstream.Position = 0;

                    model.ByteArr = rstream.ToArray();

                }

                using (MemoryStream stream = new MemoryStream())
                {
                    string html = string.Empty;
                    bool isGzip = false;

                    if (dicHeaders.ContainsKey("content-encoding"))
                    {
                        if (dicHeaders["content-encoding"].ToLower().Contains("gzip"))
                        {
                            isGzip = true;

                        }
                    }

                    if (isGzip)
                    {
                        using (MemoryStream cms = new MemoryStream(model.ByteArr))
                        {
                            using (System.IO.Compression.GZipStream gzip = new System.IO.Compression.GZipStream(cms, System.IO.Compression.CompressionMode.Decompress))
                            {
                                byte[] bytes = new byte[1024];
                                int len = 0;
                                //读取压缩流，同时会被解压
                                while ((len = gzip.Read(bytes, 0, bytes.Length)) > 0)
                                {
                                    stream.Write(bytes, 0, len);
                                }
                            }
                        }
                    }
                    else
                    {
                        stream.Write(model.ByteArr, 0, model.ByteArr.Length);
                    }

                    stream.Position = 0;

                    using (StreamReader reader = new StreamReader(stream, encoding))
                    {
                        html = reader.ReadToEnd();
                    }


                    string ed = Regex.Match(html, "charset=(?<深秋术师>(.*?))\"").Groups["深秋术师"].Value;//by 深秋术师

                    if (ed != ec && !string.IsNullOrEmpty(ed))
                    {
                        try
                        {
                            encoding = Encoding.GetEncoding(ed);
                            model.Html = encoding.GetString(model.ByteArr);
                        }
                        catch
                        {
                            model.Html = html;
                        }

                    }
                    else
                    {
                        model.Html = html;
                    }
                }

            }
            catch
            {

            }

            finally
            {
                if(inernetOpenHandel>0)
                ///关闭请求
                InternetCloseHandle(inernetOpenHandel);

                if (internetConnectionHandel > 0)
                    InternetCloseHandle(internetConnectionHandel);

                if (internetHandel > 0)
                    InternetCloseHandle(internetHandel);

                OneTimeContentHeads.Clear();
            }

            return model;
        }
        #endregion

        /// <summary>
        /// 清理string类型Cookie.剔除无用项返回结果为null时遇见错误.
        /// </summary>
        /// <param name="Cookies"></param>
        /// <returns></returns>
        public string ClearCookie(string Cookies)
        {
            try
            {
                string cookieStr = string.Empty;
                Cookies = Cookies.Replace(";", "; ");

                Regex r = new Regex("(?<=)(?<cookie>[^ ]+=(?!deleted;)[^;]+);");
                MatchCollection ms = r.Matches(Cookies);
                foreach (Match m in ms)
                {
                    if (m.Groups["cookie"].Value.Trim().ToLower().StartsWith("domain=") || m.Groups["cookie"].Value.Trim().ToLower().StartsWith("expires="))
                    {
                        continue;
                    }

                    if (m.Groups["cookie"].Value.Trim().ToLower().StartsWith("path="))
                    {
                        if (m.Groups["cookie"].Value.Trim().EndsWith(";"))
                        {
                            if (m.Groups["cookie"].Value.Length > 6)
                            {
                                string cst = m.Groups["cookie"].Value.Replace(" ", "").Remove(0, 7);
                                if (!string.IsNullOrEmpty(cst))
                                    cookieStr += cst;
                            }
                        }
                        else
                        {
                            if (m.Groups["cookie"].Value.Length > 6)
                            {
                                string cst = m.Groups["cookie"].Value.Replace(" ", "").Remove(0, 7);
                                if (!string.IsNullOrEmpty(cst))
                                    cookieStr += cst + ";";
                            }
                        }
                        continue;
                    }
                    if (!m.Groups["cookie"].Value.Trim().EndsWith(";"))
                    {
                        cookieStr += m.Groups["cookie"].Value + ";";
                    }
                    else
                    {
                        cookieStr += m.Groups["cookie"].Value;
                    }
                }

                if (!cookieStr.EndsWith(";"))
                {
                    cookieStr += ";";
                }
                return cookieStr;
            }
            catch
            {
                return string.Empty;
            }
        }
        /// <summary>
        /// 获取指定url的所有cookie
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        public string GetCookies(string url)
        {
            uint pcchCookieData = 0x100;
            StringBuilder pchCookieData = new StringBuilder((int)pcchCookieData);
            if (!InternetGetCookieEx(url, null, pchCookieData, ref pcchCookieData, 0x2000, IntPtr.Zero))
            {
                if (pcchCookieData < 0) return null;
                pchCookieData = new StringBuilder((int)pcchCookieData);
                if (!InternetGetCookieEx(url, null, pchCookieData, ref pcchCookieData, 0x2000, IntPtr.Zero)) return null;
            }
            return pchCookieData.ToString();
        }

        /// <summary>
        /// cookie字符串转换CookieContainer
        /// </summary>
        /// <param name="url"></param>
        /// <param name="cookie"></param>
        /// <returns></returns>
        public CookieContainer GetCookieContainer(string url, string cookie)
        {
            CookieContainer myCookieContainer = new CookieContainer();
            string str = cookie;
            int index = url.IndexOf("//");
            if (index > -1) url = url.Remove(0, index + 2);
            index = url.IndexOf(".com");
            if (index > -1) url = url.Substring(0, index + 4);
            foreach (string str2 in str.Split(new char[] { ';' }))
            {
                string[] strArray2 = str2.Split(new char[] { '=' });
                string str3 = str2.Replace(strArray2[0] + "=", "");
                Cookie cookie2 = new Cookie(strArray2[0].Trim().ToString(), str3)
                {
                    Domain = url
                };
                try
                {
                    myCookieContainer.Add(cookie2);
                }
                catch
                {
                    cookie2.Value = "\"" + cookie2.Value + "\"";
                    myCookieContainer.Add(cookie2);
                }
            }
            return myCookieContainer;
        }

        /// <summary>
        /// 清空所有cookie信息
        /// </summary>
        public static void ResetCookie()
        {
            // RunCmd("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2");      SuppressWininetBehavior();
            ShellExecute(IntPtr.Zero, "open", "rundll32.exe", " InetCpl.cpl,ClearMyTracksByProcess 2", "", 0);
        }

        /// <summary>
        /// 清除所有浏览器使用记录
        /// </summary>
        public static void ResetAll()
        {
            //RunCmd("RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255");
            ShellExecute(IntPtr.Zero, "open", "rundll32.exe", " InetCpl.cpl,ClearMyTracksByProcess 255", "", 0);
        }


        /// <summary>
        /// 删除Url参数
        /// </summary>
        /// <param name="url">url地址</param>
        /// <param name="k">参数名</param>
        /// <returns></returns>
        public static string RemoveUrlParame(string url, string k)
        {
            string lastUrl = url;
            string s = string.Empty;
            string key = string.Format("&{0}=", k);
            url = url.Replace("?", "&");
            int index = url.IndexOf(key);

            if (index < 0)
            {
                return lastUrl;
            }

            url = url.Remove(0, index);

            int lastIndex = url.IndexOf("&", key.Length);

            if (lastIndex != -1)
            {
                s = url.Substring(0, lastIndex);
            }
            else
            {
                s = url;
            }

            return lastUrl.Replace(s, "");
        }

        /// <summary>
        /// 获取Url参数
        /// </summary>
        /// <param name="url"></param>
        /// <param name="k"></param>
        /// <returns></returns>
        public static string GetUrlParame(string url, string k)
        {
            try
            {
                string lastUrl = url;
                string s = string.Empty;
                string key = string.Format("&{0}=", k);
                url = url.Replace("?", "&");
                int index = url.IndexOf(key);

                if (index < 0)
                {
                    return "";
                }

                url = url.Remove(0, index);

                int lastIndex = url.IndexOf("&", key.Length);

                if (lastIndex != -1)
                {
                    s = url.Substring(0, lastIndex);
                }
                else
                {
                    s = url;
                }


                return s.Remove(0, key.Length);
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string GetUrlParame(string url)
        {
            int index = url.IndexOf("?");
            url = url.Remove(0, index + 1);
            if (url.EndsWith("&"))
            {
                url = url.Remove(url.Length - 1, 1);
            }
            return url;
        }

        /// <summary>
        /// 拼合并且更新Cookie
        /// </summary>
        /// <param name="cookie1">旧cookie</param>
        /// <param name="cookie2">新cookie</param>
        /// <returns></returns>
        public string ConcatAndUpdateCookies(string cookie1, string cookie2)
        {
            var oldDic = GetDictionaryFormCookieString(cookie1);
            var newDic = GetDictionaryFormCookieString(cookie2);

            foreach (var cookie in newDic)
            {
                if (oldDic.ContainsKey(cookie.Key))
                {
                    oldDic[cookie.Key] = cookie.Value;
                }
                else
                {
                    oldDic.Add(cookie.Key, cookie.Value);
                }
            }

            StringBuilder rcsb = new StringBuilder();
            foreach (var c in oldDic)
            {
                rcsb.AppendFormat("{0}={1};", c.Key, c.Value);
            }

            if (rcsb.Length > 0)
                rcsb.Remove(rcsb.Length - 1, 1);

            return rcsb.ToString();
        }


        private Dictionary<string, string> GetDictionaryFormCookieString(string cookie1)
        {

            Dictionary<string, string> dicCookie = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(cookie1))
            {
                return dicCookie;
            }

            string[] cookieArr = cookie1.Split(';');

            foreach (string cookie in cookieArr)
            {
                try
                {
                    if (string.IsNullOrEmpty(cookie.Trim()))
                    {
                        continue;
                    }
                    string cc = cookie.Trim();
                    string[] keyAndValue = cc.Split('=');
                    string key = keyAndValue[0];
                    string value = string.Empty;
                    if (keyAndValue.Length == 2)
                        value = keyAndValue[1].Trim();
                    else
                        value = cc.Remove(0, key.Length + 1);


                    if (dicCookie.ContainsKey(key))
                    {
                        dicCookie[key] = value;
                    }
                    else
                    {
                        dicCookie.Add(key, value);
                    }
                }
                catch {
                    continue;
                }
            }

            return dicCookie;
        }

        

        [DllImport("shell32.dll")]
        static extern IntPtr ShellExecute(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, int nShowCmd);
    }
}
