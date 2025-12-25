// Source: busboy - lib/types/multipart.js (simplified)
// This is the multipart parser used by Next.js/Express

'use strict';

const { Readable } = require('stream');
const { inherits } = require('util');

// Busboy parses multipart differently than Go's mime package

function Multipart(boy, cfg) {
  // IMPORTANT: Busboy uses the FIRST boundary parameter if duplicates exist
  // This is different from Go's mime.ParseMediaType which may behave differently
  
  this.boundary = cfg.boundary;
  this.limits = cfg.limits;
  
  // Character set handling
  // Busboy supports multiple charsets for field values:
  // - utf-8 (default)
  // - utf16le / ucs2 (decoded using Buffer's ucs2Slice)
  // - base64 (decoded, though buggy - encodes instead of decodes in some versions)
  // - binary / latin1
  
  this._charset = cfg.defCharset || 'utf-8';
}

Multipart.prototype._onHeaderField = function(data) {
  // Parse headers for each part
  // Content-Type header in part can specify charset
  // Example: Content-Type: text/plain; charset=utf16le
  
  // CRITICAL: If multiple Content-Type headers exist in a part,
  // Busboy uses the FIRST one, not the last!
};

Multipart.prototype._decodeFieldValue = function(value, charset) {
  // Decodes the field value based on charset
  
  charset = (charset || this._charset).toLowerCase();
  
  switch (charset) {
    case 'utf-8':
    case 'utf8':
      return value.toString('utf8');
      
    case 'utf-16le':
    case 'utf16le':
    case 'ucs-2':
    case 'ucs2':
      // IMPORTANT: Decodes UTF-16LE encoded data
      // This means: h\x00e\x00l\x00l\x00o\x00 becomes "hello"
      // WAF sees raw bytes with nulls, but backend sees decoded string!
      return value.toString('utf16le');
      
    case 'base64':
      // Note: There's a bug in some versions where this encodes instead of decodes
      return Buffer.from(value.toString(), 'base64').toString('utf8');
      
    case 'binary':
    case 'latin1':
    case 'iso-8859-1':
      return value.toString('latin1');
      
    default:
      return value.toString('utf8');
  }
};

Multipart.prototype._onPartData = function(data) {
  // Called when part data is received
  // The charset from Content-Type header is used to decode
};

// Boundary parsing
// IMPORTANT: Busboy may handle malformed boundaries differently than Go
// - Trailing spaces after boundary markers
// - Content after closing boundary --boundary--
// - Multiple closing boundaries

Multipart.prototype._parseContentDisposition = function(header) {
  // Parses Content-Disposition header
  // Example: form-data; name="field"; filename="file.txt"
};

module.exports = Multipart;

