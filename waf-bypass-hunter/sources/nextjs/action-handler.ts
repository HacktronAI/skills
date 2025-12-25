// Source: next.js - packages/next/src/server/app-render/action-handler.ts (simplified)
// This handles Server Actions in Next.js

import { Readable } from 'stream';
import Busboy from 'busboy';

// Simplified action handler showing how multipart is processed

export async function handleAction(req: IncomingMessage) {
  const contentType = req.headers['content-type'] || '';
  
  if (contentType.includes('multipart/form-data')) {
    // Parse multipart using Busboy
    const formData = await parseMultipartFormData(req, contentType);
    
    // Process the action with parsed form data
    // If formData contains malicious payload, RCE can occur
    return executeServerAction(formData);
  }
  
  // Handle other content types...
}

async function parseMultipartFormData(req: IncomingMessage, contentType: string) {
  return new Promise((resolve, reject) => {
    const busboy = Busboy({ 
      headers: { 'content-type': contentType },
      // defCharset is important - determines how values are decoded
      defCharset: 'utf-8'
    });
    
    const formData = new Map();
    
    busboy.on('field', (name, value, info) => {
      // 'value' is already decoded by Busboy based on charset
      // If charset was utf16le, the value is decoded from UTF-16LE
      // This is where the parser differential occurs:
      // - WAF sees raw bytes: h\x00e\x00l\x00l\x00o\x00
      // - Backend receives decoded: "hello"
      
      formData.set(name, value);
    });
    
    busboy.on('file', (name, stream, info) => {
      // File upload handling...
    });
    
    busboy.on('finish', () => {
      resolve(formData);
    });
    
    busboy.on('error', reject);
    
    req.pipe(busboy);
  });
}

// The vulnerability: certain payloads can trigger prototype pollution
// or code execution when processed by the server action
function executeServerAction(formData: Map<string, any>) {
  // If formData contains :constructor or __proto__ patterns,
  // and they bypass the WAF, malicious code can execute
  
  // Example vulnerable pattern:
  // formData.get("0") = '{"get":"$1:constructor:constructor"}'
  // This can lead to RCE through prototype pollution
}

