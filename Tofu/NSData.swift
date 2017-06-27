import Foundation

private enum Base32DecodedByte {
  case valid(UInt8)
  case invalid
  case padding
}

private let padding: UInt8 = 61 // =

private let byteMappings: [CountableRange<UInt8>] = [
  65 ..< 91, // A-Z
  50 ..< 56, // 2-7
]

private func base32DecodeByte(_ byte: UInt8) -> Base32DecodedByte {
  guard byte != padding else { return .padding }
  var decodedStart: UInt8 = 0
  for range in byteMappings {
    if range.contains(byte) {
      let result = decodedStart + (byte - range.lowerBound)
      return .valid(result)
    }
    decodedStart += range.upperBound - range.lowerBound
  }
  return .invalid
}

private func decodedBytes(_ bytes: [UInt8]) -> [UInt8]? {
  var decodedBytes = [UInt8]()
  decodedBytes.reserveCapacity(bytes.count / 8 * 5)

  var decodedByte: UInt8 = 0
  var characterCount = 0
  var paddingCount = 0
  var index = 0

  for byte in bytes {
    let value: UInt8

    switch base32DecodeByte(byte) {
    case .valid(let v):
      value = v
      characterCount += 1
    case .invalid:
      return nil
    case .padding:
      paddingCount += 1
      continue
    }

    // Padding found in the middle of the sequence is invalid
    if paddingCount > 0 { return nil }

    switch index % 8 {
    case 0:
      decodedByte = value << 3
    case 1:
      decodedByte |= value >> 2
      decodedBytes.append(decodedByte)
      decodedByte = value << 6
    case 2:
      decodedByte |= value << 1
    case 3:
      decodedByte |= value >> 4
      decodedBytes.append(decodedByte)
      decodedByte = value << 4
    case 4:
      decodedByte |= value >> 1
      decodedBytes.append(decodedByte)
      decodedByte = value << 7
    case 5:
      decodedByte |= value << 2
    case 6:
      decodedByte |= value >> 3
      decodedBytes.append(decodedByte)
      decodedByte = value << 5
    case 7:
      decodedByte |= value
      decodedBytes.append(decodedByte)
    default:
      fatalError()
    }

    index += 1
  }

  let characterCountIsValid = [0, 2, 4, 5, 7].contains(characterCount % 8)
  let paddingCountIsValid = paddingCount == 0 || (characterCount + paddingCount) % 8 == 0
  guard characterCountIsValid && paddingCountIsValid else { return nil }

  return decodedBytes
}

extension Data {
  init?(base32EncodedString string: String) {
    let encodedBytes = Array(string.uppercased().utf8)
    guard let decodedBytes = decodedBytes(encodedBytes) else {
      self.init() // https://bugs.swift.org/browse/SR-704
      return nil
    }
    self.init(bytes: decodedBytes)
  }
}
