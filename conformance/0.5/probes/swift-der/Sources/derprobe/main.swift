// CryptoKit DER acceptance probe for colophon-0.5 §16.3. Run: swift run -c release derprobe
// Results depend on the platform's CryptoKit; run it on every platform that shipped the Swift apps.
import CryptoKit
import Foundation
let n: [UInt8] = [0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51]
func sub(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { var r = [UInt8](repeating: 0, count: 32); var borrow = 0
  for i in (0..<32).reversed() { var d = Int(a[i]) - Int(b[i]) - borrow; borrow = d < 0 ? 1 : 0; if d < 0 { d += 256 }; r[i] = UInt8(d) }; return r }
func strip(_ x: [UInt8]) -> [UInt8] { Array(x.drop(while: { $0 == 0 })) }
func intDER(_ x: [UInt8], pad: Int = 0) -> [UInt8] { var v = strip(x); if v.first! >= 0x80 { v.insert(0, at: 0) }
  v = [UInt8](repeating: 0, count: pad) + v; return [0x02, UInt8(v.count)] + v }
func unpadded(_ x: [UInt8]) -> [UInt8] { let v = strip(x); return [0x02, UInt8(v.count)] + v }
func seq(_ body: [UInt8], long: Bool = false) -> [UInt8] { long ? [0x30, 0x81, UInt8(body.count)] + body : [0x30, UInt8(body.count)] + body }
var tally: [String: (tried: Int, accepted: Int)] = [:]
@MainActor func check(_ name: String, _ der: [UInt8], _ key: P256.Signing.PrivateKey, _ msg: Data) {
  let parsed = try? P256.Signing.ECDSASignature(derRepresentation: Data(der))
  let ok = parsed.map { key.publicKey.isValidSignature($0, for: msg) } ?? false
  var t = tally[name] ?? (0, 0); t.tried += 1; if ok { t.accepted += 1 }; tally[name] = t
}
for _ in 0..<200 {
  let key = P256.Signing.PrivateKey(); let msg = Data("colophon".utf8)
  let raw = [UInt8](try! key.signature(for: msg).rawRepresentation)
  let r = Array(raw[0..<32]); let s = Array(raw[32..<64]); let sHigh = sub(n, s)
  check("minimal", seq(intDER(r) + intDER(s)), key, msg)
  check("high-S", seq(intDER(r) + intDER(sHigh)), key, msg)
  check("extra leading zero on r", seq(intDER(r, pad: 1) + intDER(s)), key, msg)
  check("extra leading zero on s", seq(intDER(r) + intDER(s, pad: 1)), key, msg)
  check("long-form sequence length", seq(intDER(r) + intDER(s), long: true), key, msg)
  check("trailing byte", seq(intDER(r) + intDER(s)) + [0x00], key, msg)
  if strip(r).first! >= 0x80 { check("r top bit set, no 0x00 pad", seq(unpadded(r) + intDER(s)), key, msg) }
  if strip(s).first! >= 0x80 { check("s top bit set, no 0x00 pad", seq(intDER(r) + unpadded(s)), key, msg) }
  if strip(sHigh).first! >= 0x80 { check("high s, top bit set, no 0x00 pad", seq(intDER(r) + unpadded(sHigh)), key, msg) }
  let rawHigh = Data(r + sHigh)
  let ok = (try? P256.Signing.ECDSASignature(rawRepresentation: rawHigh)).map { key.publicKey.isValidSignature($0, for: msg) } ?? false
  var t = tally["raw high-S"] ?? (0, 0); t.tried += 1; if ok { t.accepted += 1 }; tally["raw high-S"] = t
}
for (name, t) in tally.sorted(by: { $0.key < $1.key }) { print("\(name): accepted \(t.accepted) of \(t.tried)") }
struct CD: Decodable { let type: String; let challenge: String }
let dup = Data(#"{"type":"webauthn.create","type":"webauthn.get","challenge":"x"}"#.utf8)
do { let d = try JSONDecoder().decode(CD.self, from: dup); print("JSONDecoder duplicate: accepted, type=\(d.type)") } catch { print("JSONDecoder duplicate: refused") }
