This application allow you to change the password attribute from an object in LDAP.

You have to rename the version you desire (en_US or pt_BR) to changeldappasswd.cgi and put it in the CGI-BIN directory from your webserver.

It only support the hash SSHA, at this moment.

In my case, my LDAP tree was modeled to have the uid field equal the email address. You may rename the HTML form mail to "User name", for example.
