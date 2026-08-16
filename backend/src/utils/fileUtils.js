const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./logger');

/**
 * Ensure directory exists
 */
const ensureDirectory = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

/**
 * Get file extension
 */
const getFileExtension = (filename) => {
  const parts = filename.split('.');
  return parts.length > 1 ? parts.pop().toLowerCase() : '';
};

/**
 * Get file size in human-readable format
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Calculate file hashes
 */
const calculateHashes = (buffer) => {
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
  return { sha256, md5, sha1 };
};

/**
 * Calculate file hashes from file path
 */
const calculateHashesFromFile = async (filePath) => {
  const buffer = await fs.promises.readFile(filePath);
  return calculateHashes(buffer);
};

/**
 * Validate PE file signature
 */
const isPEFile = (buffer) => {
  if (buffer.length < 2) return false;
  // Check for MZ header
  return buffer[0] === 0x4D && buffer[1] === 0x5A;
};

/**
 * Validate ELF file signature
 */
const isELFFile = (buffer) => {
  if (buffer.length < 4) return false;
  return buffer[0] === 0x7F && buffer[1] === 0x45 && 
         buffer[2] === 0x4C && buffer[3] === 0x46;
};

/**
 * Detect file type from buffer
 */
const detectFileType = (buffer) => {
  if (isPEFile(buffer)) return 'pe';
  if (isELFFile(buffer)) return 'elf';
  return 'unknown';
};

/**
 * Detect PE subtype from buffer
 */
const detectPESubtype = (buffer) => {
  try {
    if (buffer.length < 0x40) return 'unknown';
    
    const peOffset = buffer.readUInt16LE(0x3C);
    if (peOffset + 4 > buffer.length) return 'unknown';
    
    if (buffer.readUInt32LE(peOffset) !== 0x00004550) return 'unknown';
    
    const characteristics = buffer.readUInt16LE(peOffset + 0x16);
    
    if (characteristics & 0x2000) return 'dll';
    if (characteristics & 0x0002) return 'exe';
    if (characteristics & 0x0100) return 'sys';
    if (characteristics & 0x0200) return 'com';
    if (characteristics & 0x0400) return 'scr';
    
    return 'exe';
  } catch (error) {
    return 'unknown';
  }
};

/**
 * Detect architecture from PE header
 */
const detectArchitecture = (buffer) => {
  try {
    if (buffer.length < 0x40) return 'unknown';
    
    const peOffset = buffer.readUInt16LE(0x3C);
    if (peOffset + 4 > buffer.length) return 'unknown';
    
    const machine = buffer.readUInt16LE(peOffset + 4);
    
    if (machine === 0x8664) return 'x64';
    if (machine === 0x14C) return 'x86';
    if (machine === 0x200) return 'x86';
    if (machine === 0xAA64) return 'x64';
    
    return 'unknown';
  } catch (error) {
    return 'unknown';
  }
};

/**
 * Sanitize filename for storage
 */
const sanitizeFilename = (filename) => {
  return filename
    .replace(/[^a-zA-Z0-9.]/g, '_')
    .replace(/_+/g, '_')
    .toLowerCase();
};

/**
 * Generate safe storage path
 */
const generateStoragePath = (hash, baseDir = 'storage/samples') => {
  const dir = path.join(process.cwd(), baseDir);
  ensureDirectory(dir);
  const filename = `${hash}.exe`;
  return path.join(dir, filename);
};

/**
 * Check if file exists at path
 */
const fileExists = (filePath) => {
  return fs.existsSync(filePath);
};

/**
 * Delete file safely
 */
const deleteFile = async (filePath) => {
  try {
    if (fs.existsSync(filePath)) {
      await fs.promises.unlink(filePath);
      return true;
    }
    return false;
  } catch (error) {
    logger.error(`Failed to delete file ${filePath}: ${error.message}`);
    return false;
  }
};

/**
 * Move file from one location to another
 */
const moveFile = async (sourcePath, destPath) => {
  try {
    await fs.promises.rename(sourcePath, destPath);
    return true;
  } catch (error) {
    // Try copy then delete
    await fs.promises.copyFile(sourcePath, destPath);
    await fs.promises.unlink(sourcePath);
    return true;
  }
};

/**
 * Get file MIME type
 */
const getMimeType = (filename) => {
  const ext = getFileExtension(filename);
  const mimeTypes = {
    exe: 'application/x-msdownload',
    dll: 'application/x-msdownload',
    sys: 'application/x-msdownload',
    scr: 'application/x-msdownload',
    com: 'application/x-msdos-program',
    zip: 'application/zip',
    rar: 'application/x-rar-compressed',
    '7z': 'application/x-7z-compressed',
    gz: 'application/gzip',
    tar: 'application/x-tar',
    cab: 'application/vnd.ms-cab-compressed',
    msi: 'application/x-msi',
    pdf: 'application/pdf',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    js: 'application/javascript',
    vbs: 'text/vbscript',
    ps1: 'text/plain',
    bat: 'text/plain',
    cmd: 'text/plain',
    jar: 'application/java-archive',
  };
  return mimeTypes[ext] || 'application/octet-stream';
};

module.exports = {
  ensureDirectory,
  getFileExtension,
  formatFileSize,
  calculateHashes,
  calculateHashesFromFile,
  isPEFile,
  isELFFile,
  detectFileType,
  detectPESubtype,
  detectArchitecture,
  sanitizeFilename,
  generateStoragePath,
  fileExists,
  deleteFile,
  moveFile,
  getMimeType,
};