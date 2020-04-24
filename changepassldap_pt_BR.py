#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''Aplicativo para troca do atributo password de um objeto LDAP'''

# changeldappass -  Permite a troca de senhas de um objeto em uma base LDAP.
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
# *** OBSERVAÇÃO *** : Neste momento suporta apenas o algorítimo de hash SSHA.
# Criado por: André Alexandre Gaio in 06/12/2007

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
msgHeader = "Página de alteração da senha de acesso ao email e navegação na Internet." # Put here your header message.

# --------------- <  End of alteration block  > ---------------

def printMsg( msg, color, foot ):
	print """Content-type: text/html\n
<html><head>
	<title>Página de troca de senha de acesso ao email e Navegação na Internet</title>
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
		print '''</font><br><br><input type='button' value='<-- Voltar' onClick='history.back()'><br></body></html>'''

def printInitial():
	print '''Content-type: text/html\n
	<html><head><title>Utilitário de troca de senhas para o LDAP</title>
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
       				<font size ="+1">Conta de email:</font>
       			</td><td>
       				<input type="text" name="name">
       			</td></tr>
  			<tr><td>
     				<font size ="+1">Senha atual:</font>
  			</td><td>
  				<input type="password" name="password">
  			</td></tr>
  			<tr><td>
  				<font size ="+1">Nova senha:</font>
  			</td><td>
  				<input type="password" name="newPass">
  			</td></tr>
			<tr><td>
				<font size ="+1">Confirme a Nova senha:</font>
			</td><td>
				<input type="password" name="newPassConf">
			</td></tr>
		</table>
		</font><br>
		<input type="submit" value="Trocar a senha"></br>
	</form>
</body></html>'''

def critForm( name, pw, npw, npwc ):
	if len( name ) >= nameLen:
		printMsg( "Erro: O nome de usuário especificado é muito longo!", "red", "f" )
		return "false"
	elif len( pw ) >= pwMaxLen:
		printMsg( "Erro: A senha possui muitos caracteres!", "red", "f" )
		return "false"
	elif len( npw ) >= pwMaxLen:
		printMsg( "Erro: A senha nova possui muitos caracteres!", "red", "f" )	
		return "false"
	elif pw == npw:
		printMsg( "Erro: A nova senha é idêntica a senha atual!", "red", "f" )	
		return "false"
	elif npw != npwc:
		printMsg( "Erro: A nova senha e a confirmação de nova senha são diferentes!", "red", "f" )
		return "false"

def genHash( pwd ):
	try:
#		salt="xx"
		ctx = sha.new( pwd )
		ctx.update( salt )
		hash = base64.b64encode( ctx.digest() + salt )
		return "{SSHA}" + hash
	except:
		printMsg( "Erro: Falha na geração da senha!<br>Acione o suporte técnico.", "red", "f" )
	
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
	printMsg( "Erro no preenchimento do formulário!<br>Por favor preencha todos os campos.", "red", "f" )
	sys.exit(0)
		
id = info["uid"]
password = info["password"]
newPass = info["newPass"]
newPassConf = info["newPassConf"]

if critForm( id, password, newPass, newPassConf ) == "false":
	sys.exit(1)

exp = re.compile( r'[#$!%&*;:(){}[]?\|/><,=+]' )

if exp.match( id ):
	printMsg( "Erro: Usuário inválido!","red", "f" )
	sys.exit (1)

try:
	l = ldap.open( ldapServer, trace_level=debugLevel )
	l.simple_bind_s( '', '' ) # Anonimous  bind
except:
	printMsg( "Erro: Problema de conexão com o servidor LDAP! Acione o suporte técnico.", "red", "f" )

P = l.search_s( base, ldap.SCOPE_SUBTREE, "uid=" + id, ['uid'] )

if len( P ) == 0:
	printMsg( "Erro: Usuário " + id + " desconhecido ou inválido!", "red", "f" )
	sys.exit (1)

dn=P[0][0]

try:
	l.simple_bind_s( dn, password )
except:
	printMsg( "Erro: Senha atual inválida!", "red", "f" )
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
	printMsg( "Erro: Falha na troca de senha! Acione o suporte técnico.<br>Motivo: " , "red", "nf" )
	print error_message
	print '''</font><br><br><input type='button' value='<-- Voltar' onClick='history.back()'><br></body></html>'''
	sys.exit (1)

printMsg( "Senha alterada com sucesso para o usuário: " + dn, "green", "f" )

