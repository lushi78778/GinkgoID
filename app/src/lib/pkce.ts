// PKCE helpers for browser

export function base64urlEncode(buf: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(buf))
  const b64 = btoa(bin)
  return b64.replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
}

export async function sha256(str: string): Promise<string> {
  const enc = new TextEncoder().encode(str)
  const digest = await crypto.subtle.digest('SHA-256', enc)
  return base64urlEncode(digest)
}

export function randomString(length = 64): string {
  const arr = new Uint8Array(length)
  crypto.getRandomValues(arr)
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
  let out = ''
  for (let i=0; i<length; i++) out += alphabet[arr[i] % alphabet.length]
  return out
}

export async function generatePKCE() {
  const verifier = randomString(64)
  const challenge = await sha256(verifier)
  return { verifier, challenge, method: 'S256' as const }
}

