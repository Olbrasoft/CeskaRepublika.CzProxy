<%@ Page Language="C#" %>
<!DOCTYPE html>
<html>
<head>
    <title>CeskaRepublika.CzProxy</title>
</head>
<body>
    <h1>CeskaRepublika.CzProxy</h1>
    <p>Czech IP media proxy for <a href="https://ceskarepublika.wiki">ceskarepublika.wiki</a></p>
    <p>Server: <%= Request.ServerVariables["SERVER_NAME"] %></p>
    <p>IP: <%= Request.ServerVariables["LOCAL_ADDR"] %></p>
    <p>Time: <%= DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") %></p>
    <p>Status: <strong style="color:green;">Running</strong></p>
</body>
</html>
