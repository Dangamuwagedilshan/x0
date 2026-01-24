const ATTESTED_DECRYPT_ACTION = `
(async () => {
  const {
    signedAttestation,
    x0PublicKey,
    ciphertext,
    dataToEncryptHash,
    accessControlConditions,
    chain,
  } = params;

  
  if (!signedAttestation || !signedAttestation.attestation || !signedAttestation.signature) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Missing or invalid signedAttestation',
        code: 'INVALID_ATTESTATION'
      })
    });
  }

  if (!x0PublicKey) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Missing x0 public key',
        code: 'MISSING_PUBLIC_KEY'
      })
    });
  }

  if (!ciphertext || !dataToEncryptHash) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Missing encryption parameters',
        code: 'MISSING_ENCRYPTION_PARAMS'
      })
    });
  }

  const attestation = signedAttestation.attestation;

  console.log('Verifying attestation signature...');
  console.log('Delegate:', attestation.delegate_id);
  console.log('Requested: $' + attestation.requested_usd);
  console.log('Remaining after: $' + attestation.remaining_after_usd);
  
  const attestationJson = JSON.stringify(attestation);
  const messageBytes = new TextEncoder().encode(attestationJson);
  
  const signatureBytes = Uint8Array.from(atob(signedAttestation.signature), c => c.charCodeAt(0));
  
  function base58Decode(str) {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let result = BigInt(0);
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      const charIndex = ALPHABET.indexOf(char);
      if (charIndex === -1) throw new Error('Invalid Base58 character: ' + char);
      result = result * BigInt(58) + BigInt(charIndex);
    }
    const bytes = [];
    while (result > 0) {
      bytes.unshift(Number(result % BigInt(256)));
      result = result / BigInt(256);
    }
    while (bytes.length < 32) {
      bytes.unshift(0);
    }
    return new Uint8Array(bytes);
  }
  
  let publicKeyBytes;
  try {
    publicKeyBytes = base58Decode(x0PublicKey);
  } catch (e) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Invalid x0 public key format: ' + e.message,
        code: 'INVALID_PUBLIC_KEY'
      })
    });
  }
  
  const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  
  if (!isValid) {
    console.error('ATTESTATION SIGNATURE VERIFICATION FAILED!');
    console.error('This could indicate tampering or key mismatch.');
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Attestation signature verification failed',
        code: 'SIGNATURE_INVALID',
        details: {
          publicKey: x0PublicKey,
          delegate_id: attestation.delegate_id,
          timestamp: attestation.timestamp_ms,
        }
      })
    });
  }
  
  console.log('Attestation signature verified successfully');

  if (attestation.remaining_after_usd < 0) {
    console.error('SPENDING LIMIT EXCEEDED!');
    console.error('Remaining after: $' + attestation.remaining_after_usd);
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Spending limit would be exceeded',
        code: 'LIMIT_EXCEEDED',
        details: {
          limit_usd: attestation.limit_usd,
          spent_usd: attestation.spent_usd,
          requested_usd: attestation.requested_usd,
          remaining_after_usd: attestation.remaining_after_usd,
        }
      })
    });
  }
  
  console.log('✓ Spending limit check passed');
  console.log('  Limit: $' + attestation.limit_usd);
  console.log('  Spent: $' + attestation.spent_usd);
  console.log('  Requested: $' + attestation.requested_usd);
  console.log('  Remaining after: $' + attestation.remaining_after_usd);
  
  const now = Date.now();
  const attestationAge = now - attestation.timestamp_ms;
  const MAX_ATTESTATION_AGE_MS = 60 * 1000;
  
  if (attestationAge < 0) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Attestation timestamp is in the future',
        code: 'FUTURE_TIMESTAMP'
      })
    });
  }
  
  if (attestationAge > MAX_ATTESTATION_AGE_MS) {
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Attestation is too old (max 1 minute)',
        code: 'STALE_ATTESTATION',
        details: {
          age_seconds: Math.round(attestationAge / 1000),
          max_age_seconds: MAX_ATTESTATION_AGE_MS / 1000,
        }
      })
    });
  }
  
  console.log('✓ Attestation timestamp is fresh (' + Math.round(attestationAge / 1000) + 's old)');
  
  console.log('Decrypting session key...');
  
  let decryptedKey;
  try {
    decryptedKey = await Lit.Actions.decryptAndCombine({
      accessControlConditions,
      ciphertext,
      dataToEncryptHash,
      chain: chain || "solana",
      authSig: null,
    });
  } catch (e) {
    console.error('Decryption failed:', e.message);
    
    return Lit.Actions.setResponse({ 
      response: JSON.stringify({ 
        success: false, 
        error: 'Key decryption failed: ' + e.message,
        code: 'DECRYPTION_FAILED'
      })
    });
  }
  
  console.log('✓ Session key decrypted successfully');
  
  return Lit.Actions.setResponse({ 
    response: JSON.stringify({ 
      success: true,
      decrypted_key: decryptedKey,
      attestation_verified: true,
      delegate_id: attestation.delegate_id,
      payment_id: attestation.payment_id,
      remaining_after_usd: attestation.remaining_after_usd,
    })
  });
})();
`;

module.exports = { ATTESTED_DECRYPT_ACTION };