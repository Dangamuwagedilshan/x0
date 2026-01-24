const LIT_ACTION_SPENDING_LIMIT = `
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

  const endpoint = apiEndpoint || 'https://api.x0.io';
  const checkUrl = endpoint + '/api/v1/internal/sessions/check-spending';
  
  console.log('Checking spending limit for session:', sessionId);
  console.log('Requested amount: $' + requestedAmountUsd);
  
  let spendingCheckResult;
  try {
    const response = await fetch(checkUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': apiKey,
        'X-Lit-Action': 'true',
      },
      body: JSON.stringify({
        session_id: sessionId,
        amount_usd: requestedAmountUsd,
        merchant_id: merchantId,
        check_type: 'crypto_enforcement',
      }),
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('Spending check API error:', response.status, errorText);
      
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
    console.error('Failed to check spending limit:', error);
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Could not verify spending limit: ' + error.message,
        code: 'NETWORK_ERROR'
      })
    });
  }

  console.log('Spending check result:', JSON.stringify(spendingCheckResult));
  
  if (!spendingCheckResult.allowed) {
    console.log('SPENDING LIMIT EXCEEDED - refusing to sign');
    
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

  console.log('Spending limit check PASSED - proceeding to sign');
  console.log('Remaining budget: $' + spendingCheckResult.remaining);

  try {
    const txBytes = Uint8Array.from(atob(transactionToSign), c => c.charCodeAt(0));
    
    const signature = await Lit.Actions.signEcdsa({
      toSign: txBytes,
      publicKey: pkpPublicKey,
      sigName: 'spending_limit_sig',
    });
    
    console.log('Transaction signed successfully');
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: true, 
        signature: signature,
        session_id: sessionId,
        amount_usd: requestedAmountUsd,
        remaining_budget: spendingCheckResult.remaining,
        crypto_enforced: true
      })
    });
    
  } catch (signError) {
    console.error('Failed to sign transaction:', signError);
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Signing failed: ' + signError.message,
        code: 'SIGNING_ERROR'
      })
    });
  }
})();
`;

const LIT_ACTION_SPENDING_LIMIT_SOLANA = `
(async () => {
  const {
    sessionId,
    requestedAmountUsd,
    merchantId,
    messageToSign,
    apiEndpoint,
    apiKey,
  } = params;

  if (!sessionId || !requestedAmountUsd || requestedAmountUsd <= 0) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Invalid parameters',
        code: 'INVALID_PARAMS'
      })
    });
  }

  const endpoint = apiEndpoint || 'https://api.x0.io';
  const checkUrl = endpoint + '/api/v1/internal/sessions/check-spending';
  
  let spendingCheck;
  try {
    const response = await fetch(checkUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': apiKey,
        'X-Lit-Action': 'true',
      },
      body: JSON.stringify({
        session_id: sessionId,
        amount_usd: requestedAmountUsd,
        merchant_id: merchantId,
        check_type: 'crypto_enforcement',
      }),
    });
    
    if (!response.ok) {
      return Lit.Actions.setResponse({ 
        response: JSON.stringify({ 
          success: false, 
          error: 'API check failed',
          code: 'API_ERROR'
        })
      });
    }
    
    spendingCheck = await response.json();
  } catch (e) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Network error during spending check',
        code: 'NETWORK_ERROR'
      })
    });
  }

  if (!spendingCheck.allowed) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: spendingCheck.reason || 'Spending limit exceeded',
        code: 'LIMIT_EXCEEDED',
        current_spent: spendingCheck.current_spent,
        limit: spendingCheck.limit,
        remaining: spendingCheck.remaining,
        crypto_enforced: true
      })
    });
  }

  try {
    const signature = await Lit.Actions.signAndCombineEcdsa({
      toSign: messageToSign,
      publicKey: pkpPublicKey,
      sigName: 'solana_spending_sig',
    });
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: true, 
        signature: signature,
        remaining_budget: spendingCheck.remaining,
        crypto_enforced: true
      })
    });
  } catch (e) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Signing failed: ' + e.message,
        code: 'SIGNING_ERROR'
      })
    });
  }
})();
`;

export const LIT_ACTIONS = {
  SPENDING_LIMIT: {
    code: LIT_ACTION_SPENDING_LIMIT,
    ipfsCid: null,
  },
  SPENDING_LIMIT_SOLANA: {
    code: LIT_ACTION_SPENDING_LIMIT_SOLANA,
    ipfsCid: null,
  },
};

export default LIT_ACTION_SPENDING_LIMIT;
