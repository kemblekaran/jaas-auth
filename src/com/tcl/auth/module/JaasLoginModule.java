package com.tcl.auth.module;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import com.tcl.auth.principal.RolePrincipal;
import com.tcl.auth.principal.UserPrincipal;

public class JaasLoginModule implements LoginModule {

	private CallbackHandler callbackHandler;
	private Subject subject;
	private UserPrincipal userPrincipal;
	private RolePrincipal rolePrincipal;
	private String login;
	private List<String> userGroups;

	@Override
	public boolean abort() throws LoginException {
		return false;
	}

	@Override
	public boolean commit() throws LoginException {
		userPrincipal = new UserPrincipal(login);
		this.subject.getPrincipals().add(userPrincipal);

		if (userGroups == null || userGroups.isEmpty()) {
			throw new IllegalArgumentException("userGroup is null/empty");
		}
		for (String userGroup : userGroups) {
			this.rolePrincipal = new RolePrincipal(userGroup);
			this.subject.getPrincipals().add(rolePrincipal);
		}
		return true;
	}

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> arg2, Map<String, ?> arg3) {
		this.callbackHandler = callbackHandler;
		this.subject = subject;
	}

	@Override
	public boolean login() throws LoginException {
		Callback callback[] = new Callback[2];
		callback[0] = new NameCallback("login");
		callback[1] = new PasswordCallback("password", true);

		try {
			callbackHandler.handle(callback);

			String name = ((NameCallback) callback[0]).getName();
			String password = String.valueOf(((PasswordCallback) callback[1]).getPassword());

			if ((name == null || password == null) || (name.isEmpty() || password.isEmpty()))
				throw new LoginException("Name and Password should not be null/empty");

			// TODO check against valid credential provider/system that has related
			// information about the userF
			if (name.equals("johndave") && password.equals("P@ssw0rd")) {
				login = name;
				userGroups = new ArrayList<>();
				userGroups.add("admin");// TODO load group of roles i.e roles from the data source or any other provider
				return true;
			}

			throw new LoginException("Authentication Failed");
		} catch (IOException e) {
			throw new LoginException(e.getMessage());
		} catch (UnsupportedCallbackException e) {
			throw new LoginException(e.getMessage());
		}
	}

	@Override
	public boolean logout() throws LoginException {
		this.subject.getPrincipals().remove(this.userPrincipal);
		this.subject.getPrincipals().remove(this.rolePrincipal);
		return true;
	}

}
