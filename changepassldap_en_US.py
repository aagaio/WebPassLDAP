#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''A little CGI to change the password attribute from an object LDAP'''

# changeldappass -  Allow to change a password from an object in LDAP.
# Copyright (C) 2006  André Alexandre Gaio <aagaio@linwork.com.br>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License (http://www.gnu.org/licenses/gpl.txt)
# for more details.
#
# *** IMPORTANT *** : At this moment, it only supports the hash SSHA.
# Made by: André Alexandre Gaio in 12/06/2007

import ldap,re,sys,base64,sha
import ldap.modlist
import cgi

# --------------- < Begin of alteration block > ---------------

ldapServer = "127.0.0.1" 	# IP address from your LDAP server.
ldapPort = 389 			# Port used for your LDAP server.
base = "c=BR"			# Base of your tree.
debugLevel = 0			# Debug level.
nameLen = 95			# Maximum name lenght.
pwMaxLen = 15			# Maximum password Lenght.
salt = "xx"			# Salt definition to make the SSHA hash.
msgHeader = "Change your mail and Internet access password" # Put here your header message.

# --------------- <  End of alteration block  > ---------------

def printMsg( msg, color, foot ):
	print """Content-type: text/html\n
<html><head>
	<title>Change your Mail and Internet access password</title>
	<meta http-equiv="Content-type" content="text/html; charset=utf-8" />
        <meta http-equiv="Content-Language" content="pt-br" />
        <meta http-equiv="Cache-Control" content="no-cache, no-store" />
        <meta http-equiv="Pragma" content="no-cache, no-store" />
        <meta http-equiv="expires" content="Mon, 06 Jan 1990 00:00:01 GMT" />
        <meta name="robots" content="index, follow" />
	</head><body>
	<h1>""" + msgHeader + """</h1><hr>
	<font color =\"""" + color + """\"size = "+2">""" + msg

	if foot == "f":
		print '''</font><br><br><input type='button' value='<-- Back' onClick='history.back()'><br></body></html>'''

def printInitial():
	print '''Content-type: text/html\n
	<html><head><title>Change your mail and Internet access password</title>
	<meta http-equiv="Content-type" content="text/html; charset=utf-8" />
	<meta http-equiv="Content-Language" content="pt-br" />
	<meta http-equiv="Cache-Control" content="no-cache, no-store" />
	<meta http-equiv="Pragma" content="no-cache, no-store" />
	<meta http-equiv="expires" content="Mon, 06 Jan 1990 00:00:01 GMT" />
	<meta name="robots" content="index, follow" />
	</head><body>
	<h1>''' + msgHeader + '''</h1><hr>
	<form method="POST" action="/cgi/changepassldap.cgi">
		<table border=0 cellspacing=2 cellpadding=4>
			<tr><td> 
       				<font size ="+1">Your email:</font>
       			</td><td>
       				<input type="text" name="name">
       			</td></tr>
  			<tr><td>
     				<font size ="+1">OLD Password:</font>
  			</td><td>
  				<input type="password" name="password">
  			</td></tr>
  			<tr><td>
  				<font size ="+1">New Password:</font>
  			</td><td>
  				<input type="password" name="newPass">
  			</td></tr>
			<tr><td>
				<font size ="+1">Confirm the a New Password:</font>
			</td><td>
				<input type="password" name="newPassConf">
			</td></tr>
		</table>
		</font><br>
		<input type="submit" value="Change my pass"></br>
	</form>
</body></html>'''

def critForm( name, pw, npw, npwc ):
	if len( name ) >= nameLen:
		printMsg( "Error: Your email address is very long!", "red", "f" )
		return "false"
	elif len( pw ) >= pwMaxLen:
		printMsg( "Error: Your password has many characters!", "red", "f" )
		return "false"
	elif len( npw ) >= pwMaxLen:
		printMsg( "Error: Your new password has many characters!", "red", "f" )	
		return "false"
	elif pw == npw:
		printMsg( "Error: Your Old password and the New Password are the same!", "red", "f" )	
		return "false"
	elif npw != npwc:
		printMsg( "Error: The new password and its confirmation are different!", "red", "f" )
		return "false"

def genHash( pwd ):
	try:
#		salt="xx"
		ctx = sha.new( pwd )
		ctx.update( salt )
		hash = base64.b64encode( ctx.digest() + salt )
		return "{SSHA}" + hash
	except:
		printMsg( "Error: Fail to generate the new password!<br>Please call the technical support.", "red", "f" )
	
# Função main

form = cgi.FieldStorage()

if len( form ) == 0:
	printInitial()
	sys.exit(0)

try:
	info = { 'uid' : form["name"].value,
		 'password' : form["password"].value,
		 'newPass' : form["newPass"].value,
		 'newPassConf' : form["newPassConf"].value }
except:
	printMsg( "Error! The form wasn't filled out correctly!<br>Please, fill out all fields.", "red", "f" )
	sys.exit(0)
		
id = info["uid"]
password = info["password"]
newPass = info["newPass"]
newPassConf = info["newPassConf"]

if critForm( id, password, newPass, newPassConf ) == "false":
	sys.exit(1)

exp = re.compile( r'[#$!%&*;:(){}[]?\|/><,=+]' )

if exp.match( id ):
	printMsg( "Error: Invalid User!","red", "f" )
	sys.exit (1)

try:
	l = ldap.open( ldapServer, trace_level=debugLevel )
	l.simple_bind_s( '', '' ) # Anonimous  bind
except:
	printMsg( "Error connecting the LDAP server! Call the technical support.", "red", "f" )

P = l.search_s( base, ldap.SCOPE_SUBTREE, "uid=" + id, ['uid'] )

if len( P ) == 0:
	printMsg( "Error: User " + id + " unknown or invalid!", "red", "f" )
	sys.exit (1)

dn=P[0][0]

try:
	l.simple_bind_s( dn, password )
except:
	printMsg( "Error: Your OLD Password is not valid!", "red", "f" )
	sys.exit (1)

S = l.search_s( base, ldap.SCOPE_SUBTREE, "uid=" + id, ['uid'] )

oldPassHash = genHash( password )
newPassHash = genHash( newPass )

old = {'userPassword':oldPassHash}
new = {'userPassword':newPassHash}

try:
	ldif = ldap.modlist.modifyModlist( old, new, ignore_oldexistent=1 )
	l.modify_s( dn, ldif )
except ldap.LDAPError, error_message:
	printMsg( "Error: Password change failed! Call the technical support.<br>Motivo: " , "red", "nf" )
	print error_message
	print '''</font><br><br><input type='button' value='<-- Back' onClick='history.back()'><br></body></html>'''
	sys.exit (1)

printMsg( "Password changed successfully for user: " + dn, "green", "f" )

