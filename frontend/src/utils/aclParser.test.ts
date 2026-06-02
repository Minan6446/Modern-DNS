import { describe, it, expect } from 'vitest'
import { parseAcl, parseAclLine } from './aclParser'

describe('parseAclLine', () => {
  it('treats empty / whitespace lines as empty', () => {
    expect(parseAclLine('', 1).kind).toBe('empty')
    expect(parseAclLine('   ', 1).kind).toBe('empty')
    expect(parseAclLine('\t', 1).kind).toBe('empty')
  })

  it('treats comments as such', () => {
    expect(parseAclLine('# office subnet', 1).kind).toBe('comment')
    expect(parseAclLine('// office', 1).kind).toBe('comment')
  })

  it('accepts BIND macros', () => {
    for (const m of ['any', 'none', 'localhost', 'localnets']) {
      const r = parseAclLine(m, 1)
      expect(r.kind).toBe('macro')
      expect(r.error).toBe('')
    }
  })

  it('accepts IPv4 and rejects out-of-range octets', () => {
    expect(parseAclLine('192.0.2.1', 1).kind).toBe('ipv4')
    expect(parseAclLine('10.0.0.255', 1).kind).toBe('ipv4')
    expect(parseAclLine('256.0.0.1', 1).kind).toBe(null)
    expect(parseAclLine('1.2.3', 1).kind).toBe(null)
  })

  it('accepts IPv4 CIDR with 0-32 mask', () => {
    expect(parseAclLine('10.0.0.0/8', 1).kind).toBe('ipv4-cidr')
    expect(parseAclLine('10.0.0.0/32', 1).kind).toBe('ipv4-cidr')
    expect(parseAclLine('10.0.0.0/33', 1).kind).toBe(null)
  })

  it('accepts IPv6 and rejects triple-colon', () => {
    expect(parseAclLine('2001:db8::1', 1).kind).toBe('ipv6')
    expect(parseAclLine('::1', 1).kind).toBe('ipv6')
    expect(parseAclLine('2001:::1', 1).kind).toBe(null)
  })

  it('accepts IPv6 CIDR with 0-128 mask', () => {
    expect(parseAclLine('2001:db8::/32', 1).kind).toBe('ipv6-cidr')
    expect(parseAclLine('::/0', 1).kind).toBe('ipv6-cidr')
    expect(parseAclLine('2001:db8::/129', 1).kind).toBe(null)
  })

  it('accepts hostnames with ≥2 labels', () => {
    expect(parseAclLine('host.example.com', 1).kind).toBe('hostname')
    expect(parseAclLine('host.example.com.', 1).kind).toBe('hostname')
    expect(parseAclLine('localhost', 1).kind).toBe('macro') // matches macro first
    expect(parseAclLine('justalabel', 1).kind).toBe(null)
  })

  it('respects negation prefix and strips it for matching', () => {
    const neg = parseAclLine('!192.0.2.1', 1)
    expect(neg.kind).toBe('ipv4')
    expect(neg.negated).toBe(true)
    expect(neg.error).toBe('')
  })

  it('rejects a lonely "!" with a useful message', () => {
    const r = parseAclLine('!', 1)
    expect(r.kind).toBe(null)
    expect(r.error).toMatch(/negation/)
  })
})

describe('parseAcl', () => {
  it('reports validEntries and errors across lines', () => {
    const text = `# office
10.0.0.0/8

192.168.1.0/24
!notanip
host.example.com`
    const s = parseAcl(text)
    expect(s.validEntries).toBe(3)
    expect(s.errors.length).toBe(1)
    expect(s.errors[0].lineNumber).toBe(5)
  })

  it('handles mixed line separators', () => {
    const s = parseAcl('10.0.0.1\r\n10.0.0.2\r10.0.0.3\n10.0.0.4')
    expect(s.validEntries).toBe(4)
    expect(s.errors.length).toBe(0)
  })

  it('returns empty summary on empty input', () => {
    const s = parseAcl('')
    expect(s.lines.length).toBe(0)
    expect(s.errors.length).toBe(0)
    expect(s.validEntries).toBe(0)
  })
})
