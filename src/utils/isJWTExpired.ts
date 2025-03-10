/**
 * Checks if a JWT is expired based on its 'exp' claim
 * @param payload - The decoded JWT payload
 * @returns true if expired, false otherwise
 */
export function isJWTExpired(payload: any): boolean {
  if (!payload.exp) return false;
  
  // JWT exp is in seconds, Date.now() is in milliseconds
  const currentTime = Math.floor(Date.now() / 1000);
  return currentTime >= payload.exp;
} 