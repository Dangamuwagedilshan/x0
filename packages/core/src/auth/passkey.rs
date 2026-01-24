use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::Html,
    Json,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeySetupStatus {
    pub platform_id: Uuid,
    pub has_passkey: bool,
    pub wallet_activated: bool,
    pub platform_name: String,
    pub wallet_address: String,
}

pub async fn get_passkey_setup_page(
    State(state): State<AppState>,
    Path(platform_id): Path<Uuid>,
) -> Result<Html<String>, StatusCode> {
    let platform = sqlx::query!(
        "SELECT name, wallet_address, wallet_type FROM platforms WHERE id = $1",
        platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let has_passkey = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE platform_id = $1 AND is_active = TRUE)",
        platform_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(false);

    let wallet_activated = !platform.wallet_address.is_empty();

    let html = render_passkey_setup_page(
        &platform.name,
        platform_id,
        has_passkey,
        wallet_activated,
        &state.config.frontend_url,
    );

    Ok(Html(html))
}

pub async fn get_passkey_status(
    State(state): State<AppState>,
    Path(platform_id): Path<Uuid>,
) -> Result<Json<PasskeySetupStatus>, StatusCode> {
    let platform = sqlx::query!(
        "SELECT name, wallet_address, wallet_type FROM platforms WHERE id = $1",
        platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let has_passkey = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE platform_id = $1 AND is_active = TRUE)",
        platform_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(false);

    Ok(Json(PasskeySetupStatus {
        platform_id,
        has_passkey,
        wallet_activated: !platform.wallet_address.is_empty(),
        platform_name: platform.name,
        wallet_address: platform.wallet_address,
    }))
}

fn render_passkey_setup_page(
    platform_name: &str,
    platform_id: Uuid,
    has_passkey: bool,
    wallet_activated: bool,
    api_base: &str,
) -> String {
    let initial_status = if wallet_activated && has_passkey {
        "completed"
    } else if has_passkey {
        "wallet_pending"
    } else {
        "ready"
    };

    format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Setup - {platform_name} | x0</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: #f6f9fc;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            color: #30313d;
        }}
        .page-header {{
            padding: 24px 32px;
        }}
        .logo {{
            font-size: 24px;
            font-weight: 700;
            color: #635bff;
            text-decoration: none;
        }}
        .main-content {{
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px 20px;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05), 0 0 0 1px rgba(0,0,0,0.05);
            max-width: 560px;
            width: 100%;
            overflow: hidden;
        }}
        .card-header {{
            padding: 40px 48px 32px;
            text-align: center;
            border-bottom: 1px solid #e0e0e0;
        }}
        .lock-icon {{
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: #f6f9fc;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #635bff;
        }}
        .card-header h1 {{ 
            font-size: 24px;
            margin-bottom: 8px;
            font-weight: 600;
            color: #30313d;
        }}
        .card-header p {{ 
            font-size: 14px;
            font-weight: 400;
            color: #697386;
            line-height: 1.6;
        }}
        .content {{ padding: 40px 48px; }}
        
        .status-card {{
            background: #f6f9fc;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 28px;
            text-align: center;
        }}
        .status-icon {{
            font-size: 48px;
            margin-bottom: 12px;
        }}
        .status-title {{
            font-size: 18px;
            font-weight: 600;
            color: #30313d;
            margin-bottom: 6px;
        }}
        .status-description {{
            color: #697386;
            font-size: 14px;
            font-weight: 400;
            line-height: 1.6;
        }}
        
        .steps {{
            background: #f6f9fc;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 28px;
        }}
        .steps-title {{
            font-size: 15px;
            font-weight: 600;
            color: #30313d;
            margin-bottom: 20px;
            text-align: center;
        }}
        .step {{
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            align-items: start;
        }}
        .step:last-child {{ margin-bottom: 0; }}
        .step-number {{
            width: 28px;
            height: 28px;
            background: #635bff;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 13px;
            flex-shrink: 0;
        }}
        .step-content {{
            flex: 1;
        }}
        .step-title {{
            font-weight: 500;
            color: #30313d;
            margin-bottom: 4px;
            font-size: 14px;
        }}
        .step-desc {{
            color: #697386;
            font-size: 13px;
            font-weight: 400;
            line-height: 1.5;
        }}
        
        .action-button {{
            background: #635bff;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            width: 100%;
            margin: 10px 0;
            transition: all 0.15s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            font-family: inherit;
        }}
        .action-button:hover {{
            background: #5851ea;
        }}
        .action-button:disabled {{
            background: #a5a5a5;
            cursor: not-allowed;
        }}
        .action-button.secondary {{
            background: white;
            color: #30313d;
            border: 1px solid #e0e0e0;
        }}
        .action-button.secondary:hover {{
            background: #f6f9fc;
        }}
        
        .spinner {{
            border: 2px solid rgba(255,255,255,0.3);
            border-top: 2px solid white;
            border-radius: 50%;
            width: 16px;
            height: 16px;
            animation: spin 0.8s linear infinite;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        
        .error-message {{
            background: #fef2f2;
            color: #dc2626;
            padding: 14px 16px;
            border-radius: 6px;
            margin: 20px 0;
            display: none;
            font-size: 14px;
            font-weight: 400;
            line-height: 1.6;
        }}
        .error-message.active {{ display: block; }}
        
        .success-message {{
            background: #f0fdf4;
            color: #16a34a;
            padding: 14px 16px;
            border-radius: 6px;
            margin: 20px 0;
            display: none;
            font-size: 14px;
            font-weight: 400;
            line-height: 1.6;
        }}
        .success-message.active {{ display: block; }}
        
        .info-box {{
            background: #f6f9fc;
            border-left: 3px solid #635bff;
            padding: 16px;
            border-radius: 0 6px 6px 0;
            margin: 24px 0;
            font-size: 14px;
            font-weight: 400;
            color: #697386;
            line-height: 1.6;
        }}
        .info-box strong {{ 
            display: block; 
            margin-bottom: 4px;
            color: #30313d;
            font-weight: 500;
        }}
        
        .wallet-info {{
            background: #f0fdf4;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            display: none;
        }}
        .wallet-info.active {{ display: block; }}
        .wallet-address {{
            font-family: 'Courier New', monospace;
            background: white;
            padding: 12px;
            border-radius: 6px;
            word-break: break-all;
            font-size: 13px;
            color: #16a34a;
            border: 1px solid #bbf7d0;
            margin-top: 10px;
        }}
        
        .footer {{
            background: #f6f9fc;
            padding: 20px 48px;
            text-align: center;
            color: #697386;
            font-size: 12px;
            font-weight: 400;
            border-top: 1px solid #e0e0e0;
        }}
        .footer a {{
            color: #635bff;
            text-decoration: none;
            font-weight: 500;
        }}
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        .hidden {{ display: none !important; }}
        
        @media (max-width: 640px) {{
            .header h1 {{ font-size: 20px; }}
            .content {{ padding: 28px 20px; }}
            .action-button {{ padding: 14px 20px; font-size: 15px; }}
        }}
        }}
    </style>
</head>
<body>
    <div class="page-header">
        <a href="/" class="logo">x0</a>
    </div>
    <div class="main-content">
        <div class="container">
            <div class="card-header">
                <div class="lock-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                </div>
                <h1>Setup Your Passkey</h1>
                <p>Secure your non-custodial MPC wallet with Face ID or Touch ID</p>
            </div>
        
        <div class="content">
            <!-- Status Card -->
            <div class="status-card" id="status-card">
                <div class="status-icon" id="status-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
                </div>
                <div class="status-title" id="status-title">Ready to Setup</div>
                <div class="status-description" id="status-description">
                    Click the button below to register your passkey and create your MPC wallet
                </div>
            </div>
            
          
            <!-- Error Message -->
            <div class="error-message" id="error-message"></div>
            
            <!-- Success Message -->
            <div class="success-message" id="success-message"></div>
            
            <!-- Info Box -->
            <div class="info-box">
                <strong><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; display: inline-block; vertical-align: text-bottom; margin-right: 6px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>Security Note</strong>
                Your private keys are never stored in one place. We use Multi-Party Computation (MPC) 
                to ensure that even we cannot access your funds. You maintain full custody through your passkey.
            </div>
            
            <!-- Action Buttons -->
            <div id="setup-section">
                <button class="action-button" id="setup-button" onclick="setupPasskey()">
                    <span>Setup Passkey Now</span>
                </button>
                <button class="action-button secondary" onclick="checkStatus()" id="check-status-btn">
                    <span>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; display: inline-block; vertical-align: text-bottom; margin-right: 6px;"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
                        Check Status
                    </span>
                </button>
            </div>
            
            <!-- Wallet Info (shown after success) -->
            <div class="wallet-info" id="wallet-info">
                <h3 style="color: #10b981; margin-bottom: 10px;">✓ Passkey & Wallet Created!</h3>
                <p style="color: #666; font-size: 14px; margin-bottom: 10px;">Your Solana wallet address:</p>
                <div class="wallet-address" id="wallet-address"></div>
            </div>
            
            <!-- Password Setup Section (shown after passkey success) -->
            <div id="password-section" style="display: none; margin-top: 24px;">
                <div class="info-box" style="background: #EEF2FF; border-left-color: #5B6EE8;">
                    <strong>🔐 Set Your Password</strong>
                    Create a password for quick email/password login. Your passkey will still be required for sensitive operations like withdrawals.
                </div>
                
                <div style="margin-top: 16px;">
                    <label style="display: block; font-size: 13px; font-weight: 500; color: #374151; margin-bottom: 6px;">Password</label>
                    <input type="password" id="password-input" placeholder="Min 8 chars, uppercase, lowercase, number" 
                        style="width: 100%; padding: 12px; border: 1px solid #E3E8EE; border-radius: 6px; font-size: 14px; margin-bottom: 12px;">
                    
                    <label style="display: block; font-size: 13px; font-weight: 500; color: #374151; margin-bottom: 6px;">Confirm Password</label>
                    <input type="password" id="confirm-password-input" placeholder="Confirm your password"
                        style="width: 100%; padding: 12px; border: 1px solid #E3E8EE; border-radius: 6px; font-size: 14px;">
                </div>
                
                <div id="password-error" style="color: #E25950; font-size: 13px; margin-top: 8px; display: none;"></div>
                
                <button class="action-button" style="margin-top: 16px;" onclick="setPassword()">
                    <span id="set-password-text">Set Password & Continue</span>
                </button>
                
                <button class="action-button secondary" style="margin-top: 8px;" onclick="skipPassword()">
                    Skip for now (use passkey only)
                </button>
            </div>
        </div>
        
        <div class="footer">
            Powered by <a href="https://x0.tech">x0</a> • Secured by WebAuthn & Lit Protocol
        </div>
    </div>
    </div>

    <script>
        const platformId = '{platform_id}';
        const apiBase = '{api_base}'.replace(/\/$/, '');
        let currentStatus = '{initial_status}';
        
        window.addEventListener('load', () => {{
            updateUIForStatus(currentStatus);
            checkStatus();
        }});
        
        async function setupPasskey() {{
            const button = document.getElementById('setup-button');
            const originalText = button.innerHTML;
            
            try {{
                button.disabled = true;
                button.innerHTML = '<div class="spinner"></div><span>Setting up...</span>';
                
                showStatus('registering', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>', 'Registering Passkey', 'Please complete the biometric authentication on your device...');
                
                console.log('Fetching platform information...');
                const statusRes = await fetch(`${{apiBase}}/api/platforms/${{platformId}}/passkey-status`);
                if (!statusRes.ok) {{
                    throw new Error('Failed to fetch platform information');
                }}
                const platformInfo = await statusRes.json();
                
                console.log('Starting WebAuthn registration...');
                const startRes = await fetch(`${{apiBase}}/api/v1/webauthn/register/start`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ 
                        platform_id: platformId,
                        email: `platform-${{platformId}}@x0.local`,
                        display_name: platformInfo.platform_name
                    }})
                }});
                
                if (!startRes.ok) {{
                    const error = await startRes.json();
                    throw new Error(error.error || 'Failed to start registration');
                }}
                
                const startData = await startRes.json();
                console.log('Registration challenge received:', startData);
                
                showStatus('authenticating', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>', 'Authenticate Now', 'Use Face ID, Touch ID, or your security key...');
                
                const options = startData.options;
                
                function base64urlToUint8Array(base64url) {{
                    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                    const padding = '='.repeat((4 - base64.length % 4) % 4);
                    const binaryString = atob(base64 + padding);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {{
                        bytes[i] = binaryString.charCodeAt(i);
                    }}
                    return bytes;
                }}
                
                const authenticatorSelection = {{
                    residentKey: 'preferred',
                    userVerification: 'preferred',
                    ...((options.publicKey.authenticatorSelection) || {{}})
                }};
                
                const publicKeyCredentialCreationOptions = {{
                    challenge: base64urlToUint8Array(options.publicKey.challenge),
                    rp: options.publicKey.rp,
                    user: {{
                        id: base64urlToUint8Array(options.publicKey.user.id),
                        name: options.publicKey.user.name,
                        displayName: options.publicKey.user.displayName
                    }},
                    pubKeyCredParams: options.publicKey.pubKeyCredParams,
                    timeout: options.publicKey.timeout || 120000,
                    attestation: options.publicKey.attestation || 'none',
                    authenticatorSelection: authenticatorSelection
                }};
                
                const credential = await navigator.credentials.create({{
                    publicKey: publicKeyCredentialCreationOptions
                }});
                
                if (!credential) {{
                    throw new Error('Failed to create passkey credential');
                }}
                
                console.log('Passkey created successfully');
                
                showStatus('creating_wallet', '⚙️', 'Creating MPC Wallet', 'Generating key shards and distributing across network...');
                
                function uint8ArrayToBase64url(buffer) {{
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) {{
                        binary += String.fromCharCode(bytes[i]);
                    }}
                    const base64 = btoa(binary);
                    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }}
                
                const credentialForServer = {{
                    id: credential.id,
                    rawId: uint8ArrayToBase64url(credential.rawId),
                    response: {{
                        clientDataJSON: uint8ArrayToBase64url(credential.response.clientDataJSON),
                        attestationObject: uint8ArrayToBase64url(credential.response.attestationObject)
                    }},
                    type: credential.type
                }};
                
                const finishRes = await fetch(`${{apiBase}}/api/v1/webauthn/register/finish`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        challenge_id: startData.challenge_id,
                        credential: credentialForServer
                    }})
                }});
                
                if (!finishRes.ok) {{
                    const error = await finishRes.json();
                    throw new Error(error.error || 'Failed to complete registration');
                }}
                
                const finishData = await finishRes.json();
                console.log('Registration completed:', finishData);
                
                if (finishData.wallet_address) {{
                    showSuccess(finishData.wallet_address);
                }} else {{
                    showStatus('success', '', 'Passkey Registered!', 'Your MPC wallet is being created. This may take a few seconds...');
                    
                    setTimeout(checkStatus, 2000);
                }}
                
            }} catch (error) {{
                console.error('Setup failed:', error);
                showError(error.message || 'Failed to setup passkey. Please try again.');
                button.disabled = false;
                button.innerHTML = originalText;
                showStatus('ready', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>', 'Ready to Setup', 'Click the button below to try again');
            }}
        }}
        
        async function checkStatus() {{
            try {{
                const res = await fetch(`${{apiBase}}/api/platforms/${{platformId}}/passkey-status`);
                if (!res.ok) throw new Error('Failed to check status');
                
                const data = await res.json();
                console.log('🔍 Passkey Status Check:', {{
                    has_passkey: data.has_passkey,
                    wallet_activated: data.wallet_activated,
                    wallet_address: data.wallet_address,
                    wallet_address_empty: !data.wallet_address || data.wallet_address === '',
                }});
                
                if (data.has_passkey && data.wallet_address && data.wallet_address !== '') {{
                    console.log('Wallet is ready! Address:', data.wallet_address);
                    showSuccess(data.wallet_address);
                }} else if (data.has_passkey) {{
                    console.log('Passkey registered, waiting for wallet creation...');
                    showStatus('wallet_pending', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>', 'Wallet Creating', 'Your passkey is registered. Wallet creation in progress...');
                    setTimeout(checkStatus, 2000);
                }} else {{
                    console.log('Ready for passkey setup');
                    showStatus('ready', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>', 'Ready to Setup', 'Click the button below to register your passkey');
                }}
            }} catch (error) {{
                console.error('Status check failed:', error);
                setTimeout(checkStatus, 3000);
            }}
        }}
        
        function showStatus(status, icon, title, description) {{
            document.getElementById('status-icon').innerHTML = icon;
            document.getElementById('status-title').textContent = title;
            document.getElementById('status-description').textContent = description;
            currentStatus = status;
        }}
        
        function showError(message) {{
            const errorEl = document.getElementById('error-message');
            errorEl.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 16px; height: 16px; display: inline-block; vertical-align: text-bottom; margin-right: 6px;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>' + message;
            errorEl.classList.add('active');
            setTimeout(() => errorEl.classList.remove('active'), 5000);
        }}
        
        function showSuccess(walletAddress) {{
            console.log('showSuccess called with wallet:', walletAddress);
            
            const setupSection = document.getElementById('setup-section');
            if (setupSection) setupSection.style.display = 'none';
            
            const walletAddressEl = document.getElementById('wallet-address');
            if (walletAddressEl) walletAddressEl.textContent = walletAddress;
            
            const walletInfoEl = document.getElementById('wallet-info');
            if (walletInfoEl) walletInfoEl.classList.add('active');
            
            const passwordSection = document.getElementById('password-section');
            if (passwordSection) passwordSection.style.display = 'block';
            
            showStatus('completed', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 48px; height: 48px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>', 'Passkey Setup Complete!', 'Now set a password for quick login access');
            
            const successEl = document.getElementById('success-message');
            if (successEl) {{
                successEl.innerHTML = '<strong>✓ Passkey registered!</strong> Your MPC wallet is active. Set a password below for email/password login.';
                successEl.classList.add('active');
            }}
        }}
        
        async function setPassword() {{
            const password = document.getElementById('password-input').value;
            const confirmPassword = document.getElementById('confirm-password-input').value;
            const errorEl = document.getElementById('password-error');
            const button = document.querySelector('#password-section .action-button');
            const buttonText = document.getElementById('set-password-text');
            
            errorEl.style.display = 'none';
            
            if (password !== confirmPassword) {{
                errorEl.textContent = 'Passwords do not match';
                errorEl.style.display = 'block';
                return;
            }}
            
            if (password.length < 8) {{
                errorEl.textContent = 'Password must be at least 8 characters';
                errorEl.style.display = 'block';
                return;
            }}
            
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            
            if (!hasUpper || !hasLower || !hasNumber) {{
                errorEl.textContent = 'Password must contain uppercase, lowercase, and a number';
                errorEl.style.display = 'block';
                return;
            }}
            
            try {{
                button.disabled = true;
                buttonText.textContent = 'Setting password...';
                
                const res = await fetch(`${{apiBase}}/api/v1/platforms/password/set`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        platform_id: platformId,
                        password: password,
                        confirm_password: confirmPassword
                    }})
                }});
                
                if (!res.ok) {{
                    const error = await res.json();
                    throw new Error(error.message || 'Failed to set password');
                }}
                
                const successEl = document.getElementById('success-message');
                successEl.innerHTML = '<strong>✓ All set!</strong> Your password has been saved. Redirecting to login...';
                
                setTimeout(() => {{
                    window.location.href = '/login';
                }}, 2000);
                
            }} catch (error) {{
                console.error('Failed to set password:', error);
                errorEl.textContent = error.message || 'Failed to set password';
                errorEl.style.display = 'block';
                button.disabled = false;
                buttonText.textContent = 'Set Password & Continue';
            }}
        }}
        
        function skipPassword() {{
            const successEl = document.getElementById('success-message');
            successEl.innerHTML = '<strong>✓ Setup complete!</strong> You can set a password later in settings. Redirecting to login...';
            setTimeout(() => {{
                window.location.href = '/login';
            }}, 2000);
        }}
        
        function updateUIForStatus(status) {{
            if (status === 'completed') {{
                document.getElementById('setup-button').style.display = 'none';
            }}
        }}
        
        function goToDashboard() {{
            window.location.href = '/login';
        }}
        
        if (!window.PublicKeyCredential) {{
            showError('WebAuthn is not supported on this device. Please use a modern browser with biometric authentication.');
            document.getElementById('setup-button').disabled = true;
        }}
    </script>
</body>
</html>
    "#,
        platform_name = platform_name,
        platform_id = platform_id,
        api_base = api_base,
        initial_status = initial_status,
    )
}
