const X0_FEE_ROUTER_PROGRAM_ID = 'BebdiSCiXfA5n9sWFJTKvekrxebWFTuqdrQ2bcBgAk7v';

const X0_FEE_WALLET = 'FM7tTDb8CSERXF6WjuTQGvba46L2r3YfCQp345RjxW52';

const LIT_ACTION_FEE_ROUTER_VALIDATION = `
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

  const FEE_ROUTER_PROGRAM_ID = '${X0_FEE_ROUTER_PROGRAM_ID}';
  const FEE_WALLET = '${X0_FEE_WALLET}';
  
  console.log('Validating transaction routes through fee router...');
  
  try {
    const txBytes = Uint8Array.from(atob(transactionToSign), c => c.charCodeAt(0));
    
    const bs58Chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    
    function bs58Decode(str) {
      const alphabet = {};
      for (let i = 0; i < bs58Chars.length; i++) {
        alphabet[bs58Chars[i]] = BigInt(i);
      }
      
      let num = BigInt(0);
      for (const char of str) {
        num = num * BigInt(58) + alphabet[char];
      }
      
      const bytes = [];
      while (num > 0) {
        bytes.unshift(Number(num % BigInt(256)));
        num = num / BigInt(256);
      }
      
      while (bytes.length < 32) {
        bytes.unshift(0);
      }
      
      return new Uint8Array(bytes);
    }
    
    const feeRouterBytes = bs58Decode(FEE_ROUTER_PROGRAM_ID);
    const feeWalletBytes = bs58Decode(FEE_WALLET);
    
    function findSequence(haystack, needle) {
      outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
        for (let j = 0; j < needle.length; j++) {
          if (haystack[i + j] !== needle[j]) continue outer;
        }
        return true;
      }
      return false;
    }
    
    const hasFeeRouter = findSequence(txBytes, feeRouterBytes);
    const hasFeeWallet = findSequence(txBytes, feeWalletBytes);
    
    if (!hasFeeRouter) {
      console.error('SECURITY: Transaction does not call x0 Fee Router program');
      return Lit.Actions.setResponse({ 
        response: JSON.stringify({ 
          success: false, 
          error: 'Transaction must route through x0 Fee Router program',
          code: 'FEE_ROUTER_MISSING',
          expected_program: FEE_ROUTER_PROGRAM_ID,
          crypto_enforced: true
        })
      });
    }
    
    if (!hasFeeWallet) {
      console.error('SECURITY: Transaction does not include x0 fee wallet');
      return Lit.Actions.setResponse({ 
        response: JSON.stringify({ 
          success: false, 
          error: 'Transaction must include x0 fee wallet',
          code: 'FEE_WALLET_MISSING',
          expected_wallet: FEE_WALLET,
          crypto_enforced: true
        })
      });
    }
    
    console.log('Fee router validation PASSED');
    
  } catch (parseError) {
    console.error('Failed to parse transaction:', parseError);
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Failed to parse transaction for validation: ' + parseError.message,
        code: 'PARSE_ERROR'
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
      sigName: 'fee_router_validated_sig',
    });
    
    console.log('Transaction signed successfully (fee router validated)');
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: true, 
        signature: signature,
        session_id: sessionId,
        amount_usd: requestedAmountUsd,
        remaining_budget: spendingCheckResult.remaining,
        fee_router_validated: true,
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

/**
 * Simplified fee router validation for Solana Ed25519 signing
 */
const LIT_ACTION_FEE_ROUTER_SOLANA = `
(async () => {
  const {
    sessionId,
    requestedAmountUsd,
    merchantId,
    messageToSign,
    accountKeys,
    apiEndpoint,
    apiKey,
  } = params;

  const FEE_ROUTER_PROGRAM_ID = '${X0_FEE_ROUTER_PROGRAM_ID}';
  const FEE_WALLET = '${X0_FEE_WALLET}';

  if (!sessionId || !requestedAmountUsd || requestedAmountUsd <= 0) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Invalid parameters',
        code: 'INVALID_PARAMS'
      })
    });
  }

  if (!accountKeys || !Array.isArray(accountKeys)) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Account keys must be provided for fee router validation',
        code: 'MISSING_ACCOUNT_KEYS'
      })
    });
  }
  
  const hasFeeRouter = accountKeys.includes(FEE_ROUTER_PROGRAM_ID);
  const hasFeeWallet = accountKeys.includes(FEE_WALLET);
  
  if (!hasFeeRouter) {
    console.error('SECURITY: Transaction does not call x0 Fee Router program');
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Transaction must route through x0 Fee Router program',
        code: 'FEE_ROUTER_MISSING',
        expected_program: FEE_ROUTER_PROGRAM_ID,
        crypto_enforced: true
      })
    });
  }
  
  if (!hasFeeWallet) {
    console.error('SECURITY: Transaction does not include x0 fee wallet');
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Transaction must include x0 fee wallet',
        code: 'FEE_WALLET_MISSING',
        expected_wallet: FEE_WALLET,
        crypto_enforced: true
      })
    });
  }
  
  console.log('Fee router validation PASSED');

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
      sigName: 'solana_fee_router_sig',
    });
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: true, 
        signature: signature,
        remaining_budget: spendingCheck.remaining,
        fee_router_validated: true,
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

export const FEE_ROUTER_LIT_ACTIONS = {
  FEE_ROUTER_VALIDATION: {
    code: LIT_ACTION_FEE_ROUTER_VALIDATION,
    ipfsCid: null,
  },
  
  /**
   * Solana-optimized fee router validation
   * Expects account keys to be pre-extracted by the caller
   */
  FEE_ROUTER_SOLANA: {
    code: LIT_ACTION_FEE_ROUTER_SOLANA,
    ipfsCid: null,
  },
};

export const FEE_ROUTER_CONSTANTS = {
  PROGRAM_ID: X0_FEE_ROUTER_PROGRAM_ID,
  FEE_WALLET: X0_FEE_WALLET,
  FEE_BASIS_POINTS: 80,
  FEE_PERCENTAGE: '0.8%',
};

export default LIT_ACTION_FEE_ROUTER_VALIDATION;
