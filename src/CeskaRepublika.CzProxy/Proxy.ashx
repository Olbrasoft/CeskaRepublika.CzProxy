<%@ WebHandler Language="C#" Class="CeskaRepublika.CzProxy.ProxyHandler" %>

namespace CeskaRepublika.CzProxy
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
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
        // Read from web.config → secrets.config (gitignored). Sync with cr-web
        // and any consumer env var on every rotation.
        private static readonly string SharedSecret =
            ConfigurationManager.AppSettings["SharedSecret"] ?? "";

        private static readonly string[] AllowedDomains = new[]
        {
            "media.cms.nova.cz",
            "nova-ott-vod-prep-sec.ssl.cdn.cra.cz",
            "prehraj.to",
            "premiumcdn.net",
            "sktorrent.eu",
            "sledujteto.cz"
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
                case "stream-resolve":
                    HandleStreamResolve(context);
                    break;
                case "resolve-and-stream":
                    HandleResolveAndStream(context);
                    break;
                case "whoami":
                    HandleWhoami(context);
                    break;
                case "sledujteto-search":
                    HandleSledujtetoSearch(context);
                    break;
                case "sledujteto-resolve":
                    HandleSledujtetoResolve(context);
                    break;
                case "sledujteto-resolve-and-stream":
                    HandleSledujtetoResolveAndStream(context);
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
                    var result = new Dictionary<string, object>
                    {
                        { "success", true },
                        { "videoUrl", videoUrl }
                    };

                    // Extract subtitle tracks (VTT files)
                    var subtitles = ExtractSubtitles(html);
                    if (subtitles.Count > 0)
                    {
                        result["subtitles"] = subtitles;
                    }

                    response.Write(Json.Serialize(result));
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

            // Validate CDN domain (premiumcdn = prehraj.to, r66nv9ed = filemoon,
            // tapecontent = streamtape, mxcontent = mixdrop)
            if (!url.Contains("premiumcdn.net") && !url.Contains("cdn")
                && !url.Contains("r66nv9ed.com") && !url.Contains("tapecontent.net")
                && !url.Contains("mxcontent.net"))
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

        // ── Resolve AND stream in one request ──────────────────────

        private void HandleResolveAndStream(HttpContext context)
        {
            var response = context.Response;
            var request = context.Request;

            var provider = (request.QueryString["provider"] ?? "").Trim().ToLower();
            var code = (request.QueryString["code"] ?? "").Trim();

            if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(code))
            {
                response.StatusCode = 400;
                response.Write("Missing provider or code");
                return;
            }

            string videoUrl = null;

            // Resolve based on provider
            if (provider == "mixdrop")
            {
                videoUrl = ResolveMixdropUrl(code);
            }
            else if (provider == "streamtape")
            {
                videoUrl = ResolveStreamtapeUrl(code);
            }

            if (string.IsNullOrEmpty(videoUrl))
            {
                response.StatusCode = 404;
                response.ContentType = "application/json";
                response.Write("{\"error\":\"Could not resolve video URL\"}");
                return;
            }

            // Stream the video bytes directly (same IP that resolved)
            try
            {
                var webRequest = (HttpWebRequest)WebRequest.Create(videoUrl);
                webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
                webRequest.Timeout = 300000;
                webRequest.ReadWriteTimeout = 300000;

                // Forward Range header for seeking
                var range = request.Headers["Range"];
                if (!string.IsNullOrEmpty(range))
                {
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
                        response.AddHeader("Content-Length", webResponse.ContentLength.ToString());

                    if (webResponse.StatusCode == HttpStatusCode.PartialContent)
                    {
                        response.StatusCode = 206;
                        var contentRange = webResponse.Headers["Content-Range"];
                        if (!string.IsNullOrEmpty(contentRange))
                            response.AddHeader("Content-Range", contentRange);
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

        // ── Debug: show outgoing IP (via api.ipify.org) + timestamp + hash for files_id ─

        private void HandleWhoami(HttpContext context)
        {
            var response = context.Response;
            response.ContentType = "application/json; charset=utf-8";
            AddCorsHeaders(response);

            var result = new Dictionary<string, object>();
            result["server_local_addr"] = context.Request.ServerVariables["LOCAL_ADDR"] ?? "";
            result["remote_addr"] = context.Request.ServerVariables["REMOTE_ADDR"] ?? "";
            result["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            try
            {
                var req = (HttpWebRequest)WebRequest.Create("https://api.ipify.org?format=json");
                req.UserAgent = "CeskaRepublika.CzProxy";
                req.Timeout = 10000;
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var stream = resp.GetResponseStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    result["outgoing_ip"] = reader.ReadToEnd();
                }
            }
            catch (Exception ex)
            {
                result["outgoing_ip_error"] = ex.Message;
            }

            var id = context.Request.QueryString["id"];
            if (!string.IsNullOrEmpty(id))
            {
                long filesId;
                if (long.TryParse(id, out filesId))
                {
                    try
                    {
                        var streamUrl = ResolveSledujtetoStreamUrl(filesId);
                        result["sledujteto_video_url"] = streamUrl;

                        // Probe the stream URL (HEAD, no redirect follow)
                        var probe = (HttpWebRequest)WebRequest.Create(streamUrl);
                        probe.Method = "GET";
                        probe.AddRange(0, 1023);
                        probe.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/142";
                        probe.Referer = "https://www.sledujteto.cz/";
                        probe.AllowAutoRedirect = false;
                        probe.Timeout = 15000;
                        try
                        {
                            using (var r = (HttpWebResponse)probe.GetResponse())
                            {
                                result["probe_status"] = (int)r.StatusCode;
                                result["probe_location"] = r.Headers["Location"] ?? "";
                                result["probe_content_type"] = r.ContentType ?? "";
                                result["probe_content_length"] = r.ContentLength;
                            }
                        }
                        catch (WebException we)
                        {
                            var r = we.Response as HttpWebResponse;
                            if (r != null)
                            {
                                result["probe_status"] = (int)r.StatusCode;
                                result["probe_location"] = r.Headers["Location"] ?? "";
                            }
                            else
                            {
                                result["probe_error"] = we.Message;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        result["sledujteto_error"] = ex.Message;
                    }
                }
            }

            response.Write(Json.Serialize(result));
        }

        // ── Sledujteto.cz search (application layer is geo-blocked from non-CZ IPs) ─

        private void HandleSledujtetoSearch(HttpContext context)
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
                var apiUrl = "https://www.sledujteto.cz/api/web/videos?query="
                    + Uri.EscapeDataString(query)
                    + "&page=1&limit=30&collection=suggestions&sort=relevance&me=0";

                var webRequest = (HttpWebRequest)WebRequest.Create(apiUrl);
                webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
                webRequest.Accept = "application/json, text/plain, */*";
                webRequest.Headers.Add("X-Requested-With", "XMLHttpRequest");
                webRequest.Headers.Add("Accept-Language", "cs,en;q=0.5");
                webRequest.Referer = "https://www.sledujteto.cz/";
                webRequest.Timeout = 15000;

                using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
                using (var stream = webResponse.GetResponseStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    // Pass upstream JSON through unchanged — cr-web parses `data.files`.
                    response.Write(reader.ReadToEnd());
                }
            }
            catch (WebException ex)
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", "Upstream " + ex.Status + ": " + ex.Message }
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

        // ── Sledujteto.cz resolve only (debug/diagnostic) ──

        private void HandleSledujtetoResolve(HttpContext context)
        {
            var response = context.Response;
            response.ContentType = "application/json; charset=utf-8";
            AddCorsHeaders(response);

            var id = (context.Request.QueryString["id"] ?? "").Trim();
            long filesId;
            if (string.IsNullOrEmpty(id) || !long.TryParse(id, out filesId))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", false },
                    { "error", "Missing or invalid id parameter" }
                }));
                return;
            }

            try
            {
                var streamUrl = ResolveSledujtetoStreamUrl(filesId);
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "success", !string.IsNullOrEmpty(streamUrl) },
                    { "video_url", streamUrl }
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

        // ── Sledujteto.cz resolve + stream (hash is IP-bound, so POST + GET must
        //    happen on the same IP — we do both here and pipe bytes to client) ─

        private void HandleSledujtetoResolveAndStream(HttpContext context)
        {
            var response = context.Response;
            var request = context.Request;

            var id = (request.QueryString["id"] ?? "").Trim();
            long filesId;
            if (string.IsNullOrEmpty(id) || !long.TryParse(id, out filesId))
            {
                response.StatusCode = 400;
                response.ContentType = "application/json";
                response.Write("{\"error\":\"Missing or invalid id parameter\"}");
                return;
            }

            string streamUrl;
            try
            {
                streamUrl = ResolveSledujtetoStreamUrl(filesId);
            }
            catch (Exception ex)
            {
                response.StatusCode = 502;
                response.ContentType = "application/json";
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "error", "Resolve failed: " + ex.Message }
                }));
                return;
            }

            if (string.IsNullOrEmpty(streamUrl))
            {
                response.StatusCode = 404;
                response.ContentType = "application/json";
                response.Write("{\"error\":\"Could not resolve sledujteto stream URL\"}");
                return;
            }

            try
            {
                var webRequest = (HttpWebRequest)WebRequest.Create(streamUrl);
                webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
                webRequest.Referer = "https://www.sledujteto.cz/";
                webRequest.Timeout = 300000;
                webRequest.ReadWriteTimeout = 300000;
                webRequest.AllowAutoRedirect = false;

                var range = request.Headers["Range"];
                if (!string.IsNullOrEmpty(range))
                {
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
                    var statusCode = (int)webResponse.StatusCode;

                    // Expose upstream redirect for debugging (e.g. invalid-file)
                    if (statusCode == 302)
                    {
                        response.StatusCode = 502;
                        response.ContentType = "application/json";
                        var location = webResponse.Headers["Location"] ?? "";
                        response.Write(Json.Serialize(new Dictionary<string, object>
                        {
                            { "error", "upstream 302 redirect (hash invalid for this IP?)" },
                            { "location", location },
                            { "stream_url", streamUrl }
                        }));
                        return;
                    }

                    response.ContentType = webResponse.ContentType ?? "video/mp4";
                    response.AddHeader("Accept-Ranges", "bytes");
                    response.AddHeader("Access-Control-Allow-Origin", "*");

                    if (webResponse.ContentLength > 0)
                        response.AddHeader("Content-Length", webResponse.ContentLength.ToString());

                    if (webResponse.StatusCode == HttpStatusCode.PartialContent)
                    {
                        response.StatusCode = 206;
                        var contentRange = webResponse.Headers["Content-Range"];
                        if (!string.IsNullOrEmpty(contentRange))
                            response.AddHeader("Content-Range", contentRange);
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

        private string ResolveSledujtetoStreamUrl(long filesId)
        {
            var payload = "{\"params\":{\"id\":" + filesId + "}}";
            var bytes = Encoding.UTF8.GetBytes(payload);

            var webRequest = (HttpWebRequest)WebRequest.Create(
                "https://www.sledujteto.cz/services/add-file-link");
            webRequest.Method = "POST";
            webRequest.ContentType = "application/json;charset=UTF-8";
            webRequest.Accept = "application/json, text/plain, */*";
            webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
            webRequest.Headers.Add("Requested-With-AngularJS", "true");
            webRequest.Headers.Add("Accept-Language", "cs,en;q=0.5");
            webRequest.Referer = "https://www.sledujteto.cz/";
            webRequest.ContentLength = bytes.Length;
            webRequest.Timeout = 15000;

            using (var reqStream = webRequest.GetRequestStream())
            {
                reqStream.Write(bytes, 0, bytes.Length);
            }

            string body;
            using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
            using (var stream = webResponse.GetResponseStream())
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                body = reader.ReadToEnd();
            }

            var data = Json.Deserialize<Dictionary<string, object>>(body);
            if (data == null) return null;

            object errObj;
            if (data.TryGetValue("error", out errObj) && errObj is bool && (bool)errObj)
            {
                object msg;
                data.TryGetValue("msg", out msg);
                throw new Exception("sledujteto error: " + (msg ?? "unknown"));
            }

            object videoUrl;
            if (data.TryGetValue("video_url", out videoUrl) && videoUrl != null)
            {
                return videoUrl.ToString();
            }

            return null;
        }

        private string ResolveMixdropUrl(string code)
        {
            var html = FetchUrl("https://mixdrop.ag/e/" + code);
            if (html.Contains("can't find") || string.IsNullOrEmpty(html)) return null;

            var packMatch = Regex.Match(html,
                @"eval\(function\(p,a,c,k,e,d\)\{.*?\}\('([^']+)',(\d+),(\d+),'([^']+)'");
            if (!packMatch.Success) return null;

            var packed = packMatch.Groups[1].Value;
            var baseN = int.Parse(packMatch.Groups[2].Value);
            var count = int.Parse(packMatch.Groups[3].Value);
            var keywords = packMatch.Groups[4].Value.Split('|');
            var unpacked = UnpackJs(packed, baseN, count, keywords);

            var wurlMatch = Regex.Match(unpacked, @"MDCore\.wurl=""([^""]+)""");
            if (!wurlMatch.Success) return null;

            var videoUrl = wurlMatch.Groups[1].Value;
            return videoUrl.StartsWith("//") ? "https:" + videoUrl : videoUrl;
        }

        private string ResolveStreamtapeUrl(string code)
        {
            var html = FetchUrl("https://streamtape.com/e/" + code);
            if (html.Contains("Video not found")) return null;

            // Pre-rendered div
            var divMatch = Regex.Match(html, @"<div[^>]*id=""robotlink""[^>]*>([^<]*get_video[^<]*)</div>");
            if (divMatch.Success)
            {
                var raw = divMatch.Groups[1].Value.Trim();
                string getVideoUrl;
                if (raw.StartsWith("//")) getVideoUrl = "https:" + raw;
                else if (raw.StartsWith("/")) getVideoUrl = "https:/" + raw;
                else getVideoUrl = "https://" + raw;

                // Follow redirect to tapecontent.net
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(getVideoUrl);
                    req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
                    req.Referer = "https://streamtape.com/";
                    req.AllowAutoRedirect = false;
                    req.Timeout = 15000;
                    using (var resp = (HttpWebResponse)req.GetResponse())
                    {
                        if ((int)resp.StatusCode == 302)
                            return resp.Headers["Location"];
                    }
                }
                catch { }

                return getVideoUrl;
            }

            return null;
        }

        // ── Stream resolve (streamtape/mixdrop → direct CDN URL) ──

        private void HandleStreamResolve(HttpContext context)
        {
            var response = context.Response;
            response.ContentType = "application/json; charset=utf-8";
            AddCorsHeaders(response);

            var provider = (context.Request.QueryString["provider"] ?? "").Trim().ToLower();
            var code = (context.Request.QueryString["code"] ?? "").Trim();

            if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(code))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", provider },
                    { "code", code },
                    { "error", "Missing provider or code" }
                }));
                return;
            }

            try
            {
                switch (provider)
                {
                    case "streamtape":
                        ResolveStreamtape(response, code);
                        break;
                    case "mixdrop":
                        ResolveMixdrop(response, code);
                        break;
                    default:
                        response.Write(Json.Serialize(new Dictionary<string, object>
                        {
                            { "provider", provider },
                            { "code", code },
                            { "error", "Unsupported provider. Use: streamtape, mixdrop" }
                        }));
                        break;
                }
            }
            catch (Exception ex)
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", provider },
                    { "code", code },
                    { "error", ex.Message }
                }));
            }
        }

        private void ResolveStreamtape(HttpResponse response, string code)
        {
            // 1. Fetch embed page
            var embedUrl = "https://streamtape.com/e/" + code;
            var html = FetchUrl(embedUrl);

            if (html.Contains("Video not found"))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", "streamtape" },
                    { "code", code },
                    { "error", "Video not found on Streamtape" }
                }));
                return;
            }

            // 2. Extract robotlink div (pre-rendered URL)
            var divMatch = Regex.Match(html, @"<div[^>]*id=""robotlink""[^>]*>([^<]*get_video[^<]*)</div>");
            string getVideoUrl = null;

            if (divMatch.Success)
            {
                var raw = divMatch.Groups[1].Value.Trim();
                if (raw.StartsWith("//"))
                    getVideoUrl = "https:" + raw;
                else if (raw.StartsWith("/"))
                    getVideoUrl = "https:/" + raw;
                else
                    getVideoUrl = "https://" + raw;
            }

            if (string.IsNullOrEmpty(getVideoUrl))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", "streamtape" },
                    { "code", code },
                    { "error", "robotlink not found in page" }
                }));
                return;
            }

            // 3. Follow redirect to get tapecontent.net CDN URL
            var webRequest = (HttpWebRequest)WebRequest.Create(getVideoUrl);
            webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
            webRequest.Referer = "https://streamtape.com/";
            webRequest.AllowAutoRedirect = false;
            webRequest.Timeout = 15000;

            using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
            {
                if ((int)webResponse.StatusCode == 302)
                {
                    var cdnUrl = webResponse.Headers["Location"];
                    response.Write(Json.Serialize(new Dictionary<string, object>
                    {
                        { "provider", "streamtape" },
                        { "code", code },
                        { "stream_url", cdnUrl },
                        { "format", "mp4" }
                    }));
                }
                else
                {
                    response.Write(Json.Serialize(new Dictionary<string, object>
                    {
                        { "provider", "streamtape" },
                        { "code", code },
                        { "error", "Expected 302 redirect, got " + (int)webResponse.StatusCode }
                    }));
                }
            }
        }

        private void ResolveMixdrop(HttpResponse response, string code)
        {
            // 1. Fetch embed page (follows redirect from mixdrop.ag to m1xdrop.click)
            var embedUrl = "https://mixdrop.ag/e/" + code;
            var html = FetchUrl(embedUrl);

            if (html.Contains("can't find") || string.IsNullOrEmpty(html))
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", "mixdrop" },
                    { "code", code },
                    { "error", "Video not found on Mixdrop" }
                }));
                return;
            }

            // 2. Extract p,a,c,k,e,d packed JS
            var packMatch = Regex.Match(html,
                @"eval\(function\(p,a,c,k,e,d\)\{.*?\}\('([^']+)',(\d+),(\d+),'([^']+)'");

            if (!packMatch.Success)
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", "mixdrop" },
                    { "code", code },
                    { "error", "p,a,c,k,e,d packed JS not found" }
                }));
                return;
            }

            var packed = packMatch.Groups[1].Value;
            var baseN = int.Parse(packMatch.Groups[2].Value);
            var count = int.Parse(packMatch.Groups[3].Value);
            var keywords = packMatch.Groups[4].Value.Split('|');

            // 3. Unpack
            var unpacked = UnpackJs(packed, baseN, count, keywords);

            // 4. Extract MDCore.wurl
            var wurlMatch = Regex.Match(unpacked, @"MDCore\.wurl=""([^""]+)""");
            if (!wurlMatch.Success)
            {
                response.Write(Json.Serialize(new Dictionary<string, object>
                {
                    { "provider", "mixdrop" },
                    { "code", code },
                    { "error", "MDCore.wurl not found in unpacked JS" }
                }));
                return;
            }

            var videoUrl = wurlMatch.Groups[1].Value;
            if (videoUrl.StartsWith("//"))
                videoUrl = "https:" + videoUrl;

            response.Write(Json.Serialize(new Dictionary<string, object>
            {
                { "provider", "mixdrop" },
                { "code", code },
                { "stream_url", videoUrl },
                { "format", "mp4" }
            }));
        }

        private string UnpackJs(string packed, int baseN, int count, string[] keywords)
        {
            return Regex.Replace(packed, @"\b\w+\b", delegate(Match m)
            {
                var word = m.Value;
                int n = DecodeBaseN(word, baseN);
                if (n >= 0 && n < count && n < keywords.Length && !string.IsNullOrEmpty(keywords[n]))
                    return keywords[n];
                return word;
            });
        }

        private int DecodeBaseN(string s, int baseN)
        {
            int result = 0;
            foreach (char ch in s)
            {
                int digit;
                if (ch >= '0' && ch <= '9') digit = ch - '0';
                else if (ch >= 'a' && ch <= 'z') digit = ch - 'a' + 10;
                else if (ch >= 'A' && ch <= 'Z') digit = ch - 'A' + 36;
                else return -1;
                if (digit >= baseN) return -1;
                result = result * baseN + digit;
            }
            return result;
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

        private List<Dictionary<string, string>> ExtractSubtitles(string html)
        {
            var subtitles = new List<Dictionary<string, string>>();

            // Match JWPlayer track objects: { file: "...vtt", label: "CZE - 123 - cze", kind: "captions" }
            var trackRegex = new Regex(
                @"\{\s*file\s*:\s*""([^""]+\.vtt[^""]*)""\s*,\s*(?:""default""\s*:\s*true\s*,\s*)?label\s*:\s*""([^""]+)""\s*,\s*kind\s*:\s*""captions""\s*\}",
                RegexOptions.IgnoreCase);

            foreach (Match match in trackRegex.Matches(html))
            {
                var vttUrl = match.Groups[1].Value.Replace("\\u0026", "&").Replace("&amp;", "&");
                var label = match.Groups[2].Value;

                // Extract language code from label like "CZE - 8929014 - cze"
                var langMatch = Regex.Match(label, @"(\w{2,3})\s*$");
                var lang = langMatch.Success ? langMatch.Groups[1].Value.ToLower() : "";

                // Clean label: "CZE - 8929014 - cze" → "CZE"
                var cleanLabel = Regex.Replace(label, @"\s*-\s*\d+\s*-\s*\w+$", "").Trim();

                subtitles.Add(new Dictionary<string, string>
                {
                    { "url", vttUrl },
                    { "lang", lang },
                    { "label", cleanLabel }
                });
            }

            return subtitles;
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
