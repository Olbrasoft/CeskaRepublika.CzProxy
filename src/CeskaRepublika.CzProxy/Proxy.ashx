<%@ WebHandler Language="C#" Class="CeskaRepublika.CzProxy.ProxyHandler" %>

namespace CeskaRepublika.CzProxy
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Web;
    using System.Web.Script.Serialization;

    /// <summary>
    /// Czech IP proxy for geo-blocked media.
    /// Supports Nova.cz embeds and prehraj.to movie search/playback.
    /// </summary>
    public class ProxyHandler : IHttpHandler
    {
        private const string SharedSecret = "***REDACTED-CR-PROXY-SECRET***";

        private static readonly string[] AllowedDomains = new[]
        {
            "media.cms.nova.cz",
            "nova-ott-vod-prep-sec.ssl.cdn.cra.cz",
            "prehraj.to",
            "premiumcdn.net"
        };

        private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

        public bool IsReusable { get { return true; } }

        public void ProcessRequest(HttpContext context)
        {
            var response = context.Response;
            var request = context.Request;
            response.TrySkipIisCustomErrors = true;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // Validate shared secret
            var key = request.QueryString["key"];
            if (string.IsNullOrEmpty(key) || key != SharedSecret)
            {
                response.StatusCode = 403;
                response.Write("Forbidden: invalid key");
                return;
            }

            // Route by action parameter
            var action = request.QueryString["action"] ?? "proxy";

            switch (action)
            {
                case "search":
                    HandleSearch(context);
                    break;
                case "video":
                    HandleVideo(context);
                    break;
                case "validate":
                    HandleValidate(context);
                    break;
                case "stream":
                    HandleStream(context);
                    break;
                default:
                    HandleProxy(context);
                    break;
            }
        }

        // ── Original Nova.cz proxy ────────────────────────────────

        private void HandleProxy(HttpContext context)
        {
            var response = context.Response;
            var request = context.Request;

            var targetUrl = request.QueryString["url"];
            if (string.IsNullOrEmpty(targetUrl))
            {
                response.StatusCode = 400;
                response.Write("Bad Request: url parameter required");
                return;
            }

            if (!IsDomainAllowed(targetUrl))
            {
                response.StatusCode = 403;
                response.Write("Forbidden: domain not whitelisted");
                return;
            }

            try
            {
                var content = FetchUrl(targetUrl);
                response.ContentType = "text/html; charset=utf-8";
                response.Write(content);
            }
            catch (WebException ex)
            {
                WriteWebException(response, ex);
            }
            catch (Exception ex)
            {
                response.StatusCode = 500;
                response.Write("Error: " + ex.GetType().Name + " - " + ex.Message);
            }
        }

        // ── Prehraj.to search ─────────────────────────────────────

        private void HandleSearch(HttpContext context)
        {
            var response = context.Response;
            response.ContentType = "application/json; charset=utf-8";
            AddCorsHeaders(response);

            var query = context.Request.QueryString["q"];
            if (string.IsNullOrEmpty(query))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", "Missing search query (q parameter)" }
                }));
                return;
            }

            try
            {
                var searchUrl = "https://prehraj.to/hledej/" + Uri.EscapeDataString(query);
                var html = FetchUrl(searchUrl);

                var movies = ParseSearchResults(html);

                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", true },
                    { "query", query },
                    { "count", movies.Count },
                    { "movies", movies }
                }));
            }
            catch (Exception ex)
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", ex.Message }
                }));
            }
        }

        // ── Prehraj.to video URL extraction ───────────────────────

        private void HandleVideo(HttpContext context)
        {
            var response = context.Response;
            response.ContentType = "application/json; charset=utf-8";
            AddCorsHeaders(response);

            var url = context.Request.QueryString["url"];
            if (string.IsNullOrEmpty(url) || !url.Contains("prehraj.to"))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", "Missing or invalid prehraj.to URL" }
                }));
                return;
            }

            try
            {
                var html = FetchUrl(url);
                var videoUrl = ExtractVideoUrl(html);

                if (videoUrl != null)
                {
                    response.Write(Json.Serialize(new Dictionary<string, object>
                    {
                        { "success", true },
                        { "videoUrl", videoUrl }
                    }));
                }
                else
                {
                    response.Write(Json.Serialize(new Dictionary<string, object>
                    {
                        { "success", false },
                        { "error", "Video URL not found in page" }
                    }));
                }
            }
            catch (Exception ex)
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", ex.Message }
                }));
            }
        }

        // ── Validate CDN URL ──────────────────────────────────────

        private void HandleValidate(HttpContext context)
        {
            var response = context.Response;
            response.ContentType = "application/json; charset=utf-8";
            AddCorsHeaders(response);

            var url = context.Request.QueryString["url"];
            if (string.IsNullOrEmpty(url))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "valid", false },
                    { "error", "Missing url parameter" }
                }));
                return;
            }

            // If prehraj.to URL, first extract video URL
            if (url.Contains("prehraj.to"))
            {
                try
                {
                    var html = FetchUrl(url);
                    var videoUrl = ExtractVideoUrl(html);
                    if (videoUrl == null)
                    {
                        response.Write(Json.Serialize(new Dictionary<string, object>
                        {
                            { "valid", false },
                            { "error", "Video URL not found" }
                        }));
                        return;
                    }
                    url = videoUrl;
                }
                catch
                {
                    response.Write(Json.Serialize(new Dictionary<string, object>
                    {
                        { "valid", false },
                        { "error", "Cannot fetch prehraj.to page" }
                    }));
                    return;
                }
            }

            try
            {
                var webRequest = (HttpWebRequest)WebRequest.Create(url);
                webRequest.Method = "GET";
                webRequest.AddRange(0, 1024);
                webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
                webRequest.Referer = "https://prehraj.to/";
                webRequest.Timeout = 20000;

                using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
                {
                    var code = (int)webResponse.StatusCode;
                    var valid = code >= 200 && code < 400;
                    response.Write(Json.Serialize(new Dictionary<string, object>
                    {
                        { "valid", valid },
                        { "status", code }
                    }));
                }
            }
            catch (WebException ex)
            {
                var httpResp = ex.Response as HttpWebResponse;
                var code = httpResp != null ? (int)httpResp.StatusCode : 0;
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "valid", false },
                    { "status", code }
                }));
            }
        }

        // ── Stream video from CDN ─────────────────────────────────

        private void HandleStream(HttpContext context)
        {
            var response = context.Response;
            var request = context.Request;

            var url = request.QueryString["url"];
            if (string.IsNullOrEmpty(url))
            {
                response.ContentType = "application/json";
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", "Missing url parameter" }
                }));
                return;
            }

            // Validate CDN domain
            if (!url.Contains("premiumcdn.net") && !url.Contains("cdn"))
            {
                response.ContentType = "application/json";
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", "URL must be from CDN" }
                }));
                return;
            }

            try
            {
                var webRequest = (HttpWebRequest)WebRequest.Create(url);
                webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
                webRequest.Referer = "https://prehraj.to/";
                webRequest.Timeout = 300000; // 5 min for streaming
                webRequest.ReadWriteTimeout = 300000;

                // Forward Range header for seeking
                var range = request.Headers["Range"];
                if (!string.IsNullOrEmpty(range))
                {
                    // Parse "bytes=START-END"
                    var rangeMatch = Regex.Match(range, @"bytes=(\d+)-(\d*)");
                    if (rangeMatch.Success)
                    {
                        long start = long.Parse(rangeMatch.Groups[1].Value);
                        if (!string.IsNullOrEmpty(rangeMatch.Groups[2].Value))
                        {
                            long end = long.Parse(rangeMatch.Groups[2].Value);
                            webRequest.AddRange(start, end);
                        }
                        else
                        {
                            webRequest.AddRange(start);
                        }
                    }
                }

                using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
                {
                    response.ContentType = webResponse.ContentType ?? "video/mp4";
                    response.AddHeader("Accept-Ranges", "bytes");
                    response.AddHeader("Access-Control-Allow-Origin", "*");

                    if (webResponse.ContentLength > 0)
                    {
                        response.AddHeader("Content-Length", webResponse.ContentLength.ToString());
                    }

                    if (webResponse.StatusCode == HttpStatusCode.PartialContent)
                    {
                        response.StatusCode = 206;
                        var contentRange = webResponse.Headers["Content-Range"];
                        if (!string.IsNullOrEmpty(contentRange))
                        {
                            response.AddHeader("Content-Range", contentRange);
                        }
                    }

                    using (var stream = webResponse.GetResponseStream())
                    {
                        var buffer = new byte[8192];
                        int bytesRead;
                        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            response.OutputStream.Write(buffer, 0, bytesRead);
                            response.Flush();
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                WriteWebException(response, ex);
            }
            catch (Exception ex)
            {
                response.StatusCode = 500;
                response.Write("Stream error: " + ex.Message);
            }
        }

        // ── Helper methods ────────────────────────────────────────

        private string FetchUrl(string url)
        {
            var webRequest = (HttpWebRequest)WebRequest.Create(url);
            webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
            webRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            webRequest.Headers.Add("Accept-Language", "cs,en;q=0.5");
            webRequest.Timeout = 30000;

            using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
            using (var stream = webResponse.GetResponseStream())
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        private bool IsDomainAllowed(string url)
        {
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri))
            {
                return false;
            }
            foreach (var domain in AllowedDomains)
            {
                if (uri.Host.EndsWith(domain, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private List<Dictionary<string, string>> ParseSearchResults(string html)
        {
            var movies = new List<Dictionary<string, string>>();
            var seen = new HashSet<string>();

            // Pattern: <a class="video..." href="/movie-name/id" title="Movie Title"
            var regex = new Regex(
                @"<a[^>]*class=""[^""]*video[^""]*""[^>]*href=""(/[a-z0-9+\-]+/[a-z0-9]+)""[^>]*title=""([^""]+)""",
                RegexOptions.IgnoreCase);

            foreach (Match match in regex.Matches(html))
            {
                var path = match.Groups[1].Value;
                if (seen.Contains(path)) continue;
                seen.Add(path);

                var title = WebUtility.HtmlDecode(match.Groups[2].Value);

                // Extract thumbnail
                var thumbnail = "";
                var thumbRegex = new Regex(
                    @"href=""" + Regex.Escape(path) + @""".*?<img[^>]*src=""([^""]+thumb[^""]*\.jpg)""",
                    RegexOptions.Singleline);
                var thumbMatch = thumbRegex.Match(html);
                if (thumbMatch.Success)
                {
                    thumbnail = thumbMatch.Groups[1].Value;
                }

                // Extract year
                var year = "";
                var yearMatch = Regex.Match(title, @"[-(](\d{4})[)-]");
                if (!yearMatch.Success)
                {
                    yearMatch = Regex.Match(path, @"-(\d{4})[-/]");
                }
                if (yearMatch.Success)
                {
                    year = yearMatch.Groups[1].Value;
                }

                movies.Add(new Dictionary<string, string>
                {
                    { "url", "https://prehraj.to" + path },
                    { "title", title },
                    { "thumbnail", thumbnail },
                    { "year", year }
                });

                if (movies.Count >= 30) break;
            }

            return movies;
        }

        private string ExtractVideoUrl(string html)
        {
            // Try multiple patterns for CDN video URLs
            string[] patterns = new[]
            {
                @"[""']?(https?://[^""']*premiumcdn\.net[^""']*\.m3u8[^""']*)[""']?",
                @"[""']?(https?://[^""']*premiumcdn\.net[^""']*\.mp4[^""']*)[""']?",
                @"[""']?(https?://[^""']*cdn[^""']*\.(m3u8|mp4)[^""']*)[""']?",
                @"<source[^>]+src=[""']([^""']+)[""'][^>]*>",
                @"""file""\s*:\s*""([^""]+)""",
                @"""src""\s*:\s*""([^""]+)""",
                @"""url""\s*:\s*""([^""]+\.m3u8[^""]*)"""
            };

            foreach (var pattern in patterns)
            {
                var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    var candidate = match.Groups[1].Value;
                    if (Regex.IsMatch(candidate, @"\.(m3u8|mp4)", RegexOptions.IgnoreCase))
                    {
                        return candidate.Replace("\\/", "/");
                    }
                }
            }

            return null;
        }

        private void AddCorsHeaders(HttpResponse response)
        {
            response.AddHeader("Access-Control-Allow-Origin", "*");
            response.AddHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        }

        private void WriteWebException(HttpResponse response, WebException ex)
        {
            var httpResponse = ex.Response as HttpWebResponse;
            if (httpResponse != null)
            {
                response.StatusCode = (int)httpResponse.StatusCode;
                using (var errStream = httpResponse.GetResponseStream())
                using (var errReader = new StreamReader(errStream))
                {
                    response.Write("Upstream " + httpResponse.StatusCode + ": " + errReader.ReadToEnd());
                }
            }
            else
            {
                response.StatusCode = 502;
                response.Write("WebException: " + ex.Status + " - " + ex.Message);
            }
        }
    }
}
