<%@ WebHandler Language="C#" Class="CeskaRepublika.CzProxy.ProxyHandler" %>

namespace CeskaRepublika.CzProxy
{
    using System;
    using System.IO;
    using System.Net;
    using System.Web;

    /// <summary>
    /// Czech IP proxy for geo-blocked media embed pages.
    /// Used by ceskarepublika.wiki to fetch Nova.cz embed pages
    /// that are blocked from foreign (non-Czech) IP addresses.
    /// </summary>
    public class ProxyHandler : IHttpHandler
    {
        // Shared secret — must match the key configured on ceskarepublika.wiki server
        private const string SharedSecret = "***REDACTED-CR-PROXY-SECRET***";

        // Only allow fetching from these domains
        private static readonly string[] AllowedDomains = new[]
        {
            "media.cms.nova.cz",
            "nova-ott-vod-prep-sec.ssl.cdn.cra.cz"
        };

        public bool IsReusable { get { return true; } }

        public void ProcessRequest(HttpContext context)
        {
            var response = context.Response;
            var request = context.Request;
            response.TrySkipIisCustomErrors = true;

            // Force TLS 1.2 for outbound HTTPS
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // Validate shared secret
            var key = request.QueryString["key"];
            if (string.IsNullOrEmpty(key) || key != SharedSecret)
            {
                response.StatusCode = 403;
                response.Write("Forbidden: invalid key");
                return;
            }

            // Get target URL
            var targetUrl = request.QueryString["url"];
            if (string.IsNullOrEmpty(targetUrl))
            {
                response.StatusCode = 400;
                response.Write("Bad Request: url parameter required");
                return;
            }

            // Validate domain whitelist
            Uri uri;
            if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out uri))
            {
                response.StatusCode = 400;
                response.Write("Bad Request: invalid URL");
                return;
            }

            bool domainAllowed = false;
            foreach (var domain in AllowedDomains)
            {
                if (uri.Host.EndsWith(domain, StringComparison.OrdinalIgnoreCase))
                {
                    domainAllowed = true;
                    break;
                }
            }

            if (!domainAllowed)
            {
                response.StatusCode = 403;
                response.Write("Forbidden: domain not whitelisted");
                return;
            }

            // Fetch the target URL from Czech IP
            try
            {
                var webRequest = (HttpWebRequest)WebRequest.Create(targetUrl);
                webRequest.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
                webRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                webRequest.Headers.Add("Accept-Language", "cs,en;q=0.5");
                webRequest.Timeout = 30000;

                using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
                using (var stream = webResponse.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    var content = reader.ReadToEnd();

                    response.ContentType = webResponse.ContentType;
                    response.StatusCode = (int)webResponse.StatusCode;
                    response.Write(content);
                }
            }
            catch (WebException ex)
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
                    response.StatusCode = 200;
                    response.Write("WebException: " + ex.Status + " - " + ex.Message);
                }
            }
            catch (Exception ex)
            {
                response.StatusCode = 200;
                response.Write("Error: " + ex.GetType().Name + " - " + ex.Message);
            }
        }
    }
}
