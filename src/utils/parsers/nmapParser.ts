import type { NormalizedScan, ParseResult } from '../../types/nmap';
import { detectFormat } from './formatDetector';
import { parseGrepableNmap } from './grepableParser';
import { parseNormalNmap } from './normalParser';
import { parseXmlNmap } from './xmlParser';

export function parseNmapScan(content: string, filename: string): ParseResult {
  const format = detectFormat(content);

  if (!content || content.trim().length === 0) {
    return {
      success: false,
      error: `File '${filename}' is completely empty. Please select a valid Nmap scan output file.`,
      formatDetected: 'unknown',
      filename
    };
  }

  try {
    let scan: NormalizedScan;

    if (format === 'xml') {
      scan = parseXmlNmap(content, filename);
    } else if (format === 'grepable') {
      scan = parseGrepableNmap(content, filename);
    } else if (format === 'normal') {
      scan = parseNormalNmap(content, filename);
    } else {
      // Fallback: try XML first, then Normal, then Grepable
      try {
        scan = parseXmlNmap(content, filename);
      } catch {
        try {
          scan = parseNormalNmap(content, filename);
        } catch {
          scan = parseGrepableNmap(content, filename);
        }
      }
    }

    if (!scan || scan.hosts.length === 0) {
      return {
        success: false,
        error: `Could not extract any host scan data from '${filename}'. Verify that this file contains valid Nmap -oX, -oN, or -oG output.`,
        formatDetected: format,
        filename
      };
    }

    return {
      success: true,
      scan,
      formatDetected: scan.meta.format,
      filename
    };
  } catch (err: any) {
    return {
      success: false,
      error: `Parse error in '${filename}': ${err.message || 'Malformed Nmap scan file structure.'}`,
      formatDetected: format,
      filename
    };
  }
}
