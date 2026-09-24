<%@ page import="java.security.SecureRandom, java.util.Base64" %>
<%
    // Generate a cryptographically secure CSRF token and store it in the session.
    // The token is unique per session and is validated by the Install servlet
    // before any state-altering database operation is performed.
    if (session.getAttribute("csrfToken") == null) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String csrfToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        session.setAttribute("csrfToken", csrfToken);
    }
    String csrfToken = (String) session.getAttribute("csrfToken");
%>

  <%@ include file="/header.jsp" %>


<form action="Install" method="POST">
<table>
    <tr><td>Website Title:</td> <td><input type="text" name="siteTitle" value="Java Vulnerable Lab"/></td></tr>
    <tr><td>Database Name:</td> <td><input type="text" name="dbname" value="abc"/></td></tr>
    <tr><td>Database User:</td> <td><input type="text" name="dbuser" value="root"/></td></tr>
     <tr><td>Database Password:</td> <td><input type="text" name="dbpass" value="root"/></td></tr>
       <tr><td>JDBC Driver:</td> <td><input type="text" name="jdbcdriver" value="com.mysql.jdbc.Driver"/></td></tr>
       <tr><td>JDBC URL:</td> <td><input type="text" name="dburl" value="jdbc:mysql://mysql:3306/"/></td></tr>
       <tr><td>Admin Login Credential:</td></tr>
       <tr><td>Username(Default):</td> <td><input type="text" name="adminuser" value="admin"/></td></tr>
       <tr><td>Password(Default):</td> <td><input type="text" name="adminpass" value="admin"/></td></tr>

       <tr><td></td></tr>
    <input type="hidden" value="1" name="setup"/>
    <!-- CSRF synchronizer token: generated per-session, validated server-side -->
    <input type="hidden" name="csrfToken" value="<%= csrfToken %>"/>
    <tr><td></td> <td><input type="submit" value="Install" name="Install"/></td></tr>
</table>
</form>
<br/>
Note:<b style="color:red">If a database already exits, it will be dropped </b>



  <%@ include file="/footer.jsp" %>
