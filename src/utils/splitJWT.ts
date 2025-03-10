/**
 * Splits a JWT into its signed data portion and signature
 * @param jwt - The JWT string
 * @returns An object with signedData and signature
 */
export function splitJWT(jwt: string): { signedData: string, signature: string } {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  
  return {
    signedData: `${parts[0]}.${parts[1]}`,
    signature: parts[2]
  };
} 