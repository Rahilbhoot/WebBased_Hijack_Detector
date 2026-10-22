import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check saved session in localStorage
    const savedToken = localStorage.getItem('auth_token');
    const savedUser = localStorage.getItem('auth_user');

    if (savedToken && savedUser) {
      try {
        setToken(savedToken);
        setUser(JSON.parse(savedUser));
      } catch (e) {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    // 1. Check if AWS Cognito environment variables are provided
    const userPoolId = import.meta.env.VITE_COGNITO_USER_POOL_ID;
    const clientId = import.meta.env.VITE_COGNITO_CLIENT_ID;

    // Standard demo / local mode if Cognito not explicitly configured or for demo user
    if (!userPoolId || !clientId || username.toLowerCase() === 'admin' || username.toLowerCase() === 'demo') {
      const demoUser = {
        username: username || 'secops-admin',
        email: `${username || 'admin'}@enterprise-soc.local`,
        role: 'SecOps Lead',
        isDemo: !userPoolId,
      };
      const demoToken = 'demo-jwt-token-' + Math.random().toString(36).substring(2);
      setUser(demoUser);
      setToken(demoToken);
      localStorage.setItem('auth_token', demoToken);
      localStorage.setItem('auth_user', JSON.stringify(demoUser));
      return { success: true };
    }

    // 2. AWS Cognito USER_PASSWORD_AUTH via AWS API
    try {
      const res = await fetch(`https://cognito-idp.${userPoolId.split('_')[0]}.amazonaws.com/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-amz-json-1.1',
          'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth',
        },
        body: JSON.stringify({
          AuthFlow: 'USER_PASSWORD_AUTH',
          ClientId: clientId,
          AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
          },
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.__type || 'Authentication failed');
      }

      const idToken = data.AuthenticationResult.IdToken;
      const cognitoUser = {
        username,
        email: username,
        role: 'SOC Analyst',
        isDemo: false,
      };

      setUser(cognitoUser);
      setToken(idToken);
      localStorage.setItem('auth_token', idToken);
      localStorage.setItem('auth_user', JSON.stringify(cognitoUser));
      return { success: true };
    } catch (err) {
      console.error('Cognito login error:', err);
      return { success: false, error: err.message };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_user');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
