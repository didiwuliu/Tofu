import Foundation

final class Password {
  var algorithm: Algorithm = .sha1
  var counter = 0
  var digits = 6
  var period = 30
  var secret = Data()
  var timeBased = false

  func valueForDate(_ date: Date) -> String {
    let counter = timeBased ?
      Int64(date.timeIntervalSince1970) / Int64(period) : Int64(self.counter)
    var input = counter.bigEndian
    let digest = UnsafeMutablePointer<UInt32>.allocate(capacity: algorithm.digestLength)
    defer { digest.deinitialize() }
    CCHmac(algorithm.hmacAlgorithm, (secret as NSData).bytes, secret.count, &input, MemoryLayout.size(ofValue: input), digest)
    let bytes = UnsafePointer<UInt32>(digest)
    let offset = bytes[algorithm.digestLength - 1] & 0x0f
    let number = UInt32(bigEndian: UnsafeRawPointer(bytes + Int(offset)).load(as: UInt32.self)) & 0x7fffffff
    return String(format: "%0\(digits)d", number % UInt32(pow(10, Float(digits))))
  }

  func progressForDate(_ date: Date) -> Double {
    return timeIntervalRemainingForDate(date) / Double(period)
  }

  func timeIntervalRemainingForDate(_ date: Date) -> Double {
    let period = Double(self.period)
    return period - (date.timeIntervalSince1970.truncatingRemainder(dividingBy: period))
  }
}
