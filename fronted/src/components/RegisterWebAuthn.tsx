import React, { useState, useEffect } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import './WebAuthn.css'; // Crearemos este archivo CSS

// Componente para registro de WebAuthn
const RegisterWebAuthn: React.FC = () => {
  const [username, setUsername] = useState<string>('');
  const [displayName, setDisplayName] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [supportInfo, setSupportInfo] = useState<{supported: boolean, platform: string}>({
    supported: false,
    platform: ''
  });
  const [savedCredentials, setSavedCredentials] = useState<any[]>([]);

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
        console.log('Credenciales cargadas:', credentials);
      }
    } catch (error) {
      console.error('Error al cargar credenciales guardadas:', error);
    }
  };

  // Guardar credencial en localStorage
  const saveCredential = (credentialData: any) => {
    try {
      const newCredential = {
        id: credentialData.id,
        rawId: credentialData.rawId,
        username: username,
        displayName: displayName,
        created: new Date().toISOString(),
        type: credentialData.type,
        rpId: window.location.hostname
      };

      const savedData = localStorage.getItem('webauthn_credentials') || '[]';
      const credentials = JSON.parse(savedData);
      
      // Verificar si ya existe esta credencial
      const exists = credentials.some((cred: any) => cred.id === newCredential.id);
      
      if (!exists) {
        credentials.push(newCredential);
        localStorage.setItem('webauthn_credentials', JSON.stringify(credentials));
        setSavedCredentials(credentials);
        console.log('Credencial guardada:', newCredential);
      }
    } catch (error) {
      console.error('Error al guardar credencial:', error);
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

  const handleRegister = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    
    if (!supportInfo.supported) {
      setStatus('WebAuthn no es compatible con este navegador');
      return;
    }
    
    if (!username) {
      setStatus('Por favor ingresa un nombre de usuario');
      return;
    }
    
    setLoading(true);
    setStatus('Iniciando registro biométrico...');

    try {
      // Generar opciones de registro localmente
      const challenge = generateChallenge();
      console.log('Challenge generado:', challenge);

      const domainName = window.location.hostname;
      const rpId = domainName.includes(':') ? 'localhost' : domainName;
      console.log("Usando rpId:", rpId);
      
      // Definir userVerification con tipo literal
      const userVerification = (supportInfo.platform === 'mobile' 
        ? 'discouraged' 
        : 'required') as 'discouraged' | 'preferred' | 'required';
      
      // Opciones para WebAuthn con tipos literales correctos
      const registrationOptions = {
        challenge,
        rp: {
          name: 'WebAuthn Demo Local',
          id: rpId,
        },
        user: {
          id: btoa(username).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
          name: username,
          displayName: displayName || username,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' as const }, // ES256
          { alg: -257, type: 'public-key' as const }, // RS256
        ],
        timeout: 60000,
        attestation: 'none' as const,
        authenticatorSelection: {
          authenticatorAttachment: 'platform' as const,
          userVerification,
          residentKey: 'required' as const,
        },
      };

      console.log('Opciones de registro:', registrationOptions);
      setStatus('Por favor completa la verificación biométrica...');

      // Usar el formato correcto con optionsJSON
      const attestationResponse = await startRegistration({
        optionsJSON: registrationOptions
      });
      
      // Guardar credencial en localStorage
      saveCredential(attestationResponse);
      
      // Mostrar la respuesta completa en consola
      console.log('------- CREDENCIAL BIOMÉTRICA REGISTRADA -------');
      console.log('Respuesta completa:', attestationResponse);
      
      // Extraer información importante
      const { id, rawId, type, response } = attestationResponse;
      
      console.log('ID de credencial:', id);
      console.log('Raw ID (base64):', rawId);
      console.log('Tipo:', type);
      
      // Verificar si authenticatorAttachment existe
      if ('authenticatorAttachment' in attestationResponse) {
        console.log('Dispositivo:', attestationResponse.authenticatorAttachment);
      }
      
      // Mostrar detalles de la respuesta
      if (response) {
        console.log('ClientDataJSON:', response.clientDataJSON);
        console.log('AttestatationObject:', response.attestationObject);
        
        if ('transports' in response) {
          console.log('Transportes disponibles:', response.transports);
        }
      }
      
      setStatus(`¡Registro exitoso! ID de credencial: ${id.substring(0, 12)}...`);
    } catch (error: unknown) {
      console.error('Error durante el registro biométrico:', error);
      
      if (error instanceof Error) {
        // Mensajes más amigables para errores comunes
        if (error.message.includes('The operation either timed out')) {
          setStatus('La operación ha expirado. Intenta nuevamente.');
        } else if (error.message.includes('already registered')) {
          setStatus('Esta credencial ya está registrada. Intenta con otro nombre de usuario.');
        } else if (error.message.includes('platform authenticator')) {
          setStatus('No se pudo acceder al autenticador biométrico del dispositivo.');
        } else {
          setStatus(`Error: ${error.message}`);
        }
      } else {
        setStatus('Error desconocido durante el registro');
      }
    } finally {
      setLoading(false);
    }
  };

  // Exportar credenciales como JSON
  const handleExportCredentials = () => {
    try {
      const dataStr = localStorage.getItem('webauthn_credentials') || '[]';
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
      
      const exportLink = document.createElement('a');
      exportLink.setAttribute('href', dataUri);
      exportLink.setAttribute('download', 'webauthn_credentials.json');
      exportLink.click();
    } catch (error) {
      console.error('Error al exportar credenciales:', error);
      setStatus('Error al exportar credenciales');
    }
  };

  // Importar credenciales desde archivo JSON
  const handleImportCredentials = (e: React.ChangeEvent<HTMLInputElement>) => {
    try {
      const file = e.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const jsonData = event.target?.result as string;
          localStorage.setItem('webauthn_credentials', jsonData);
          loadSavedCredentials();
          setStatus('Credenciales importadas correctamente');
        } catch (error) {
          console.error('Error al procesar el archivo:', error);
          setStatus('Error al importar credenciales');
        }
      };
      reader.readAsText(file);
    } catch (error) {
      console.error('Error al importar credenciales:', error);
      setStatus('Error al importar credenciales');
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
          <h2>Registrar credencial biométrica</h2>
          <p>Los datos se guardarán localmente para pruebas</p>
        </div>
        
        {!supportInfo.supported ? (
          <div className="webauthn-error">
            <i className="icon-error"></i>
            <p>Tu navegador no es compatible con WebAuthn. Por favor usa Chrome, Safari o Edge actualizado.</p>
          </div>
        ) : null}
        
        <form onSubmit={handleRegister} className="webauthn-form">
          <div className="form-group">
            <label htmlFor="username">Nombre de usuario</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
              required
              disabled={loading}
              className="webauthn-input"
              placeholder="Ingresa un nombre de usuario"
            />
          </div>
          <div className="form-group">
            <label htmlFor="displayName">Nombre para mostrar</label>
            <input
              id="displayName"
              type="text"
              value={displayName}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setDisplayName(e.target.value)}
              required
              disabled={loading}
              className="webauthn-input"
              placeholder="Nombre completo o apodo"
            />
          </div>
          <button 
            type="submit" 
            disabled={loading || !supportInfo.supported}
            className={`webauthn-button ${loading ? 'loading' : ''} ${!supportInfo.supported ? 'disabled' : ''}`}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                <span>Procesando...</span>
              </>
            ) : (
              <>
                <i className="icon-fingerprint"></i>
                <span>Registrar biometría</span>
              </>
            )}
          </button>
        </form>
        
        {status && (
          <div className={`webauthn-status ${status.includes('Error') || status.includes('expirado') ? 'error' : status.includes('exitoso') ? 'success' : ''}`}>
            <p>{status}</p>
          </div>
        )}
        
        <WebAuthnSupportInfo />

        {/* Sección de credenciales guardadas */}
        <div className="credentials-section">
          <h3>Credenciales guardadas ({savedCredentials.length})</h3>
          
          <div className="credentials-actions">
            <button 
              onClick={handleExportCredentials}
              className="secondary-button"
              disabled={savedCredentials.length === 0}
            >
              Exportar credenciales
            </button>
            
            <label className="import-button">
              Importar credenciales
              <input 
                type="file" 
                accept=".json" 
                onChange={handleImportCredentials}
                style={{ display: 'none' }}
              />
            </label>
          </div>
          
          <div className="credentials-list">
            {savedCredentials.length > 0 ? (
              savedCredentials.map((cred, index) => (
                <div key={index} className="credential-item">
                  <div className="credential-header">
                    <span className="credential-user">{cred.username}</span>
                    <span className="credential-date">{new Date(cred.created).toLocaleString()}</span>
                  </div>
                  <div className="credential-id">ID: {cred.id.substring(0, 15)}...</div>
                </div>
              ))
            ) : (
              <p className="no-credentials">No hay credenciales guardadas aún</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegisterWebAuthn;