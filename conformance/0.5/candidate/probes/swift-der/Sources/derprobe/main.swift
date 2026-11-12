import CryptoKit
import Foundation
let n: [UInt8] = [0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51]
func sub(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { var r = [UInt8](repeating: 0, count: 32); var borrow = 0
  for i in (0..<32).reversed() { var d = Int(a[i]) - Int(b[i]) - borrow; borrow = d < 0 ? 1 : 0; if d < 0 { d += 256 }; r[i] = UInt8(d) }; return r }
func intDER(_ x: [UInt8], pad: Int = 0) -> [UInt8] { var v = Array(x.drop(while: { $0 == 0 })); if v.first! >= 0x80 { v.insert(0, at: 0) }
  v = [UInt8](repeating: 0, count: pad) + v; return [0x02, UInt8(v.count)] + v }
func seq(_ body: [UInt8], long: Bool = false) -> [UInt8] { long ? [0x30, 0x81, UInt8(body.count)] + body : [0x30, UInt8(body.count)] + body }
let key = P256.Signing.PrivateKey(); let msg = Data("colophon".utf8)
var sig = try! key.signature(for: msg); var raw = [UInt8](sig.rawRepresentation)
let r = Array(raw[0..<32]); var s = Array(raw[32..<64])
let sHigh = sub(n, s)
let cases: [(String, [UInt8])] = [
  ("minimal", seq(intDER(r) + intDER(s))),
  ("high-S", seq(intDER(r) + intDER(sHigh))),
  ("extra leading zero on r", seq(intDER(r, pad: 1) + intDER(s))),
  ("long-form sequence length", seq(intDER(r) + intDER(s), long: true)),
  ("trailing byte", seq(intDER(r) + intDER(s)) + [0x00]),
  ("long-form integer length", seq([0x02, 0x81, UInt8(intDER(r).count - 2)] + Array(intDER(r).dropFirst(2)) + intDER(s))),
  ("negative r (no 0x00 pad)", { var v = Array(r.drop(while: { $0 == 0 })); return seq([0x02, UInt8(v.count)] + v + intDER(s)) }()),
]
for (name, der) in cases {
  let parsed = try? P256.Signing.ECDSASignature(derRepresentation: Data(der))
  let valid = parsed.map { key.publicKey.isValidSignature($0, for: msg) } ?? false
  print("\(name): parses=\(parsed != nil) valid=\(valid)")
}
// raw: high-S, and r/s >= n
let rawHigh = Data(r + sHigh)
print("raw high-S: parses=\((try? P256.Signing.ECDSASignature(rawRepresentation: rawHigh)) != nil) valid=\((try? P256.Signing.ECDSASignature(rawRepresentation: rawHigh)).map { key.publicKey.isValidSignature($0, for: msg) } ?? false)")
// JSONDecoder duplicate keys
struct CD: Decodable { let type: String; let challenge: String }
let dup = Data(#"{"type":"webauthn.create","type":"webauthn.get","challenge":"x"}"#.utf8)
do { let d = try JSONDecoder().decode(CD.self, from: dup); print("JSONDecoder duplicate: accepted, type=\(d.type)") } catch { print("JSONDecoder duplicate: refused \(error)") }
