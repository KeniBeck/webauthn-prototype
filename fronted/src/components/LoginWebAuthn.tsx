import React, { useState, useEffect } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import './WebAuthn.css';

const LoginWebAuthn: React.FC = () => {
  const [username, setUsername] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [supportInfo, setSupportInfo] = useState<{supported: boolean, platform: string}>({
    supported: false,
    platform: ''
  });
  const [savedCredentials, setSavedCredentials] = useState<any[]>([]);
  const [selectedCredential, setSelectedCredential] = useState<string>('');

  // Verificar soporte al cargar el componente
  useEffect(() => {
    const checkSupport = async () => {
      const isSupported = window.PublicKeyCredential !== undefined;
      const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
      
      setSupportInfo({
        supported: isSupported,
        platform: isMobile ? 'mobile' : 'desktop'
      });
      
      if (!isSupported) {
        setStatus('WebAuthn no es compatible con este navegador');
      }

      // Cargar credenciales guardadas
      loadSavedCredentials();
    };
    
    checkSupport();
  }, []);

  // Cargar credenciales guardadas desde localStorage
  const loadSavedCredentials = () => {
    try {
      const savedData = localStorage.getItem('webauthn_credentials');
      if (savedData) {
        const credentials = JSON.parse(savedData);
        setSavedCredentials(credentials);
        console.log('Credenciales cargadas para autenticación:', credentials);
      }
    } catch (error) {
      console.error('Error al cargar credenciales guardadas:', error);
    }
  };

  // Función para generar un desafío aleatorio de 32 bytes en base64
  const generateChallenge = (): string => {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    
    // Convertir a string base64 y formatear para URL
    return btoa(String.fromCharCode(...Array.from(array)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const handleSelectCredential = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const credId = e.target.value;
    setSelectedCredential(credId);
    
    // Encontrar y establecer el nombre de usuario correspondiente
    const credential = savedCredentials.find(cred => cred.id === credId);
    if (credential) {
      setUsername(credential.username);
    }
  };

  const handleLogin = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    
    if (!supportInfo.supported) {
      setStatus('WebAuthn no es compatible con este navegador');
      return;
    }
    
    setLoading(true);
    setStatus('Iniciando autenticación biométrica...');

    try {
      // Generar opciones de autenticación localmente
      const challenge = generateChallenge();
      console.log('Challenge generado:', challenge);

      const domainName = window.location.hostname;
      const rpId = domainName.includes(':') ? 'localhost' : domainName;
      console.log("Usando rpId:", rpId);
      
      // Definir userVerification con tipo literal
      const userVerification = (supportInfo.platform === 'mobile' 
        ? 'discouraged' 
        : 'required') as 'discouraged' | 'required';
      
      // Opciones de autenticación
      const authOptions: any = {
        challenge,
        rpId,
        timeout: 60000,
        userVerification,
      };

      // Si hay una credencial seleccionada, la incluimos en las opciones
      if (selectedCredential) {
        authOptions.allowCredentials = [{
          id: selectedCredential,
          type: 'public-key',
          transports: ['internal']
        }];
      }

      console.log('Opciones de autenticación:', authOptions);
      setStatus('Por favor completa la verificación biométrica...');

      // Usar formato correcto con optionsJSON
      const authResponse = await startAuthentication({
        optionsJSON: authOptions
      });
      
      // Mostrar respuesta en consola
      console.log('------- AUTENTICACIÓN BIOMÉTRICA COMPLETADA -------');
      console.log('Respuesta completa:', authResponse);
      
      // Extraer información importante
      const { id, rawId, type, response } = authResponse;
      
      console.log('ID de credencial:', id);
      console.log('Raw ID (base64):', rawId);
      console.log('Tipo:', type);
      
      // Buscar el usuario asociado a esta credencial
      const matchedCredential = savedCredentials.find(cred => cred.id === id);
      const authenticatedUser = matchedCredential ? matchedCredential.username : 'Usuario desconocido';
      
      // Mostrar detalles de la respuesta
      if (response) {
        console.log('ClientDataJSON:', response.clientDataJSON);
        console.log('AuthenticatorData:', response.authenticatorData);
        console.log('Signature:', response.signature);
        console.log('UserHandle:', response.userHandle);
      }
      
      setStatus(`¡Autenticación exitosa! Bienvenido ${authenticatedUser}`);
    } catch (error: unknown) {
      console.error('Error durante la autenticación biométrica:', error);
      
      if (error instanceof Error) {
        // Mensajes más amigables para errores comunes
        if (error.message.includes('The operation either timed out')) {
          setStatus('La operación ha expirado. Intenta nuevamente.');
        } else if (error.message.includes('no available credentials')) {
          setStatus('No se encontraron credenciales. Registra una credencial primero.');
        } else {
          setStatus(`Error: ${error.message}`);
        }
      } else {
        setStatus('Error desconocido durante la autenticación');
      }
    } finally {
      setLoading(false);
    }
  };

  // Componente para mostrar información de soporte
  const WebAuthnSupportInfo = () => (
    <div className="webauthn-support-info">
      <h3>Información de soporte:</h3>
      <ul>
        <li>WebAuthn soportado: <strong>{supportInfo.supported ? 'Sí' : 'No'}</strong></li>
        <li>Tipo de dispositivo: <strong>{supportInfo.platform}</strong></li>
        <li>Hostname: <strong>{window.location.hostname}</strong></li>
        <li>Protocolo: <strong>{window.location.protocol}</strong></li>
      </ul>
    </div>
  );

  return (
    <div className="webauthn-container">
      <div className="webauthn-card">
        <div className="webauthn-header">
          <h2>Autenticación biométrica</h2>
          <p>Verificación con credenciales guardadas localmente</p>
        </div>
        
        {!supportInfo.supported ? (
          <div className="webauthn-error">
            <i className="icon-error"></i>
            <p>Tu navegador no es compatible con WebAuthn. Por favor usa Chrome, Safari o Edge actualizado.</p>
          </div>
        ) : null}
        
        <form onSubmit={handleLogin} className="webauthn-form">
          {savedCredentials.length > 0 && (
            <div className="form-group">
              <label htmlFor="credentialSelect">Seleccionar credencial</label>
              <select 
                id="credentialSelect"
                value={selectedCredential}
                onChange={handleSelectCredential}
                className="webauthn-select"
                disabled={loading}
              >
                <option value="">-- Seleccionar credencial --</option>
                {savedCredentials.map((cred, index) => (
                  <option key={index} value={cred.id}>
                    {cred.username} ({cred.id.substring(0, 10)}...)
                  </option>
                ))}
              </select>
            </div>
          )}
          
          <div className="form-group">
            <label htmlFor="loginUsername">Nombre de usuario</label>
            <input
              id="loginUsername"
              type="text"
              value={username}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
              disabled={loading || selectedCredential !== ''}
              className="webauthn-input"
              placeholder="Ingresa un nombre de usuario"
            />
          </div>
          
          <button 
            type="submit" 
            disabled={loading || !supportInfo.supported || (savedCredentials.length > 0 && !selectedCredential)}
            className={`webauthn-button ${loading ? 'loading' : ''} ${!supportInfo.supported ? 'disabled' : ''}`}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                <span>Verificando...</span>
              </>
            ) : (
              <>
                <i className="icon-lock-open"></i>
                <span>Verificar biometría</span>
              </>
            )}
          </button>
        </form>
        
        {status && (
          <div className={`webauthn-status ${status.includes('Error') || status.includes('expirado') ? 'error' : status.includes('exitosa') ? 'success' : ''}`}>
            <p>{status}</p>
          </div>
        )}
        
        <WebAuthnSupportInfo />

        {/* Sección de credenciales disponibles */}
        {savedCredentials.length > 0 ? (
          <div className="credentials-section">
            <h3>Credenciales disponibles ({savedCredentials.length})</h3>
            <div className="credentials-list">
              {savedCredentials.map((cred, index) => (
                <div 
                  key={index} 
                  className={`credential-item ${selectedCredential === cred.id ? 'selected' : ''}`}
                  onClick={() => setSelectedCredential(cred.id)}
                >
                  <div className="credential-header">
                    <span className="credential-user">{cred.username}</span>
                    <span className="credential-date">{new Date(cred.created).toLocaleString()}</span>
                  </div>
                  <div className="credential-id">ID: {cred.id.substring(0, 15)}...</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="no-credentials-message">
            <p>No hay credenciales guardadas. Por favor registra una credencial primero.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoginWebAuthn;