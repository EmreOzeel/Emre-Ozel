/**
 * Maps raw backend error strings to user-friendly messages.
 * Raw Python exceptions must never be shown directly in the UI.
 */

export type AnalysisErrorCode =
  | 'tshark_missing'
  | 'tshark_broken'
  | 'empty_capture'
  | 'zero_output'
  | 'unreliable_extraction'
  | 'unknown'

export interface AnalysisErrorInfo {
  code: AnalysisErrorCode
  title: string
  message: string
  hint: string
}

interface ErrorPattern {
  patterns: RegExp[]
  code: AnalysisErrorCode
  title: string
  message: string
  hint: string
}

const ERROR_PATTERNS: ErrorPattern[] = [
  {
    patterns: [
      /tshark is required/i,
      /not found on this system/i,
      /tshark not found/i,
    ],
    code: 'tshark_missing',
    title: 'tshark Not Installed',
    message: 'Packet analysis requires tshark, which is not installed on the server.',
    hint: 'Run: apt-get install -y tshark wireshark-common  — then restart the backend.',
  },
  {
    patterns: [
      /tshark is installed but failed/i,
      /failed to execute/i,
    ],
    code: 'tshark_broken',
    title: 'tshark Error',
    message: 'tshark is installed but failed to run correctly.',
    hint: 'Try: apt-get install --reinstall tshark wireshark-common',
  },
  {
    patterns: [
      /could not read any packets/i,
      /empty.*corrupt/i,
      /empty, corrupted/i,
      /unsupported format/i,
    ],
    code: 'empty_capture',
    title: 'Cannot Read Capture File',
    message: 'The capture file could not be read. It may be empty, corrupted, or in an unsupported format.',
    hint: 'Verify the file is a valid .pcap or .pcapng capture and try re-exporting it.',
  },
  {
    patterns: [
      /produced no output/i,
      /no parseable packet data/i,
      /field names were rejected/i,
      /incompatible with the expected field set/i,
    ],
    code: 'zero_output',
    title: 'Packet Extraction Failed',
    message: 'tshark could not extract packet data from this file.',
    hint: 'This is usually a tshark version incompatibility. Check backend logs for rejected field names.',
  },
  {
    patterns: [
      /extraction is unreliable/i,
      /malformed.*field/i,
      /field separator/i,
      /field-to-column mapping/i,
      /essential field.*absent/i,
    ],
    code: 'unreliable_extraction',
    title: 'Unreliable Packet Extraction',
    message:
      'Packet extraction produced inconsistent results and was stopped to prevent inaccurate analysis.',
    hint:
      'The capture may be truncated, or the tshark version on this server is not compatible with the expected field set.',
  },
]

export function classifyAnalysisError(rawError: string | null | undefined): AnalysisErrorInfo {
  const text = rawError ?? ''
  for (const entry of ERROR_PATTERNS) {
    if (entry.patterns.some((p) => p.test(text))) {
      return {
        code: entry.code,
        title: entry.title,
        message: entry.message,
        hint: entry.hint,
      }
    }
  }
  return {
    code: 'unknown',
    title: 'Analysis Failed',
    message: 'The analysis could not be completed.',
    hint: 'Check the server logs for more details.',
  }
}
