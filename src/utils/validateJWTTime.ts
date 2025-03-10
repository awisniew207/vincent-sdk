/**
 * Validates JWT time claims (iat and nbf)
 * @param payload - The decoded JWT payload
 * @returns true if time claims are valid, false otherwise
 */
export function validateJWTTime(payload: any): boolean {
  const currentTime = Math.floor(Date.now() / 1000);
  
  // Check 'not before' claim if present
  if (payload.nbf && currentTime < payload.nbf) {
    return false;
  }
  
  // Check 'issued at' claim if present
  // Allow a small leeway (30 seconds) for clock skew
  if (payload.iat && currentTime < payload.iat - 30) {
    return false;
  }
  
  return true;
} 