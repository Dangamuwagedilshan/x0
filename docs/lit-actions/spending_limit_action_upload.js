(async () => {
  const {
    sessionId,
    requestedAmountUsd,
    merchantId,
    transactionToSign,
    apiEndpoint,
    apiKey,
  } = params;

  if (!sessionId || typeof sessionId !== 'string') {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Invalid session_id',
        code: 'INVALID_SESSION'
      })
    });
  }

  if (!requestedAmountUsd || typeof requestedAmountUsd !== 'number' || requestedAmountUsd <= 0) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Invalid requested amount',
        code: 'INVALID_AMOUNT'
      })
    });
  }

  if (!transactionToSign || typeof transactionToSign !== 'string') {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'No transaction provided to sign',
        code: 'NO_TRANSACTION'
      })
    });
  }

  const endpoint = apiEndpoint || 'https://api.x0.tech';
  const checkUrl = endpoint + '/api/v1/internal/sessions/check-spending';
  
  console.log('[x0 Lit Action] Checking spending limit');
  console.log('  Session:', sessionId);
  console.log('  Amount: $' + requestedAmountUsd);
  
  let spendingCheckResult;
  try {
    const headers = {
      'Content-Type': 'application/json',
      'X-Lit-Action': 'true',
      'User-Agent': 'x0-Lit-Action/1.0'
    };
    
    if (apiKey) {
      headers['Authorization'] = 'Bearer ' + apiKey;
    }
    
    const response = await fetch(checkUrl, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({
        session_id: sessionId,
        amount_usd: requestedAmountUsd,
        merchant_id: merchantId,
        check_type: 'crypto_enforcement',
      }),
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('[x0 Lit Action] API error:', response.status, errorText);
      
      return Lit.Actions.setResponse({ 
        response: JSON.stringify({ 
          success: false, 
          error: 'Spending check failed: ' + errorText,
          code: 'API_ERROR',
          status: response.status
        })
      });
    }
    
    spendingCheckResult = await response.json();
  } catch (error) {
    console.error('[x0 Lit Action] Network error:', error);
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Could not verify spending limit: ' + error.message,
        code: 'NETWORK_ERROR'
      })
    });
  }

  console.log('[x0 Lit Action] Spending check result:', JSON.stringify(spendingCheckResult));
  
  if (!spendingCheckResult.allowed) {
    console.log('[x0 Lit Action] LIMIT EXCEEDED - refusing to sign');
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: spendingCheckResult.reason || 'Spending limit exceeded',
        code: 'LIMIT_EXCEEDED',
        current_spent: spendingCheckResult.current_spent,
        limit: spendingCheckResult.limit,
        remaining: spendingCheckResult.remaining,
        crypto_enforced: true
      })
    });
  }

  if (!spendingCheckResult.session_valid) {
    console.log('[x0 Lit Action] SESSION INVALID - refusing to sign');
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Session is invalid or expired',
        code: 'SESSION_INVALID',
        crypto_enforced: true
      })
    });
  }

  console.log('[x0 Lit Action] Limit check PASSED - signing transaction');
  console.log('  Remaining budget: $' + spendingCheckResult.remaining);

  try {
    const txBytes = Uint8Array.from(atob(transactionToSign), c => c.charCodeAt(0));
    
    const sigShare = await Lit.Actions.signEcdsa({
      toSign: txBytes,
      publicKey: pkpPublicKey,
      sigName: 'x0_spending_limit_sig',
    });
    
    console.log('[x0 Lit Action] Transaction signed successfully');
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: true, 
        signature: sigShare.signature,
        publicKey: sigShare.publicKey,
        recid: sigShare.recid,
        session_id: sessionId,
        amount_usd: requestedAmountUsd,
        remaining_budget: spendingCheckResult.remaining,
        crypto_enforced: true
      })
    });
    
  } catch (signError) {
    console.error('[x0 Lit Action] Signing failed:', signError);
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Signing failed: ' + signError.message,
        code: 'SIGNING_ERROR'
      })
    });
  }
})();
