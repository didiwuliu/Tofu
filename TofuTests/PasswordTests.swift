import XCTest
@testable import Tofu

class PasswordTests: XCTestCase {
  func testValueForDate() {
    let secret = "12345678901234567890".data(using: String.Encoding.ascii)!
    let counterBasedTests: [(Int, String, String, String)] = [
      (0, "755224", "875740", "125165"),
      (1, "287082", "247374", "342147"),
      (2, "359152", "254785", "730102"),
      (3, "969429", "496144", "778726"),
      (4, "338314", "480556", "937510"),
      (5, "254676", "697997", "848329"),
      (6, "287922", "191609", "266680"),
      (7, "162583", "579288", "588359"),
      (8, "399871", "895912", "039399"),
      (9, "520489", "184989", "643409"),
    ]
    let timeBasedTests = [
      (Date(timeIntervalSince1970: 59), "94287082", "32247374", "69342147"),
      (Date(timeIntervalSince1970: 1111111109), "07081804", "34756375", "63049338"),
      (Date(timeIntervalSince1970: 1111111111), "14050471", "74584430", "54380122"),
      (Date(timeIntervalSince1970: 1234567890), "89005924", "42829826", "76671578"),
      (Date(timeIntervalSince1970: 2000000000), "69279037", "78428693", "56464532"),
      (Date(timeIntervalSince1970: 20000000000), "65353130", "24142410", "69481994"),
    ]
    let counterBasedSHA1Password = passwordWithSecret(secret, algorithm: .sha1, digits: 6,
      timeBased: false)
    let counterBasedSHA256Password = passwordWithSecret(secret, algorithm: .sha256, digits: 6,
      timeBased: false)
    let counterBasedSHA512Password = passwordWithSecret(secret, algorithm: .sha512, digits: 6,
      timeBased: false)
    let timeBasedSHA1Password = passwordWithSecret(secret, algorithm: .sha1, digits: 8,
      timeBased: true)
    let timeBasedSHA256Password = passwordWithSecret(secret, algorithm: .sha256, digits: 8,
      timeBased: true)
    let timeBasedSHA512Password = passwordWithSecret(secret, algorithm: .sha512, digits: 8,
      timeBased: true)

    for (counter, expSHA1, expSHA256, expSHA512) in counterBasedTests {
      counterBasedSHA1Password.counter = counter
      XCTAssertEqual(counterBasedSHA1Password.valueForDate(Date()), expSHA1)
      counterBasedSHA256Password.counter = counter
      XCTAssertEqual(counterBasedSHA256Password.valueForDate(Date()), expSHA256)
      counterBasedSHA512Password.counter = counter
      XCTAssertEqual(counterBasedSHA512Password.valueForDate(Date()), expSHA512)
    }

    for (date, expSHA1, expSHA256, expSHA512) in timeBasedTests {
      XCTAssertEqual(timeBasedSHA1Password.valueForDate(date), expSHA1)
      XCTAssertEqual(timeBasedSHA256Password.valueForDate(date), expSHA256)
      XCTAssertEqual(timeBasedSHA512Password.valueForDate(date), expSHA512)
    }
  }

  func testProgressForDate() {
    let password = Password()
    password.period = 30

    XCTAssertEqual(password.progressForDate(Date(timeIntervalSince1970: 0)), 1)
    XCTAssertEqual(password.progressForDate(Date(timeIntervalSince1970: 15)), 0.5)
    XCTAssertEqual(password.progressForDate(Date(timeIntervalSince1970: 22.5)), 0.25)
    XCTAssertEqual(password.progressForDate(Date(timeIntervalSince1970: 30)), 1)
  }

  func timeIntervalRemainingForDate() {
    let password = Password()
    password.period = 30

    XCTAssertEqual(password.timeIntervalRemainingForDate(Date(timeIntervalSince1970: 0)), 30)
    XCTAssertEqual(password.timeIntervalRemainingForDate(Date(timeIntervalSince1970: 15)), 15)
    XCTAssertEqual(password.timeIntervalRemainingForDate(Date(timeIntervalSince1970: 22.5)), 7.5)
    XCTAssertEqual(password.timeIntervalRemainingForDate(Date(timeIntervalSince1970: 30)), 0)
  }

  fileprivate func passwordWithSecret(_ secret: Data, algorithm: Algorithm, digits: Int,
    timeBased: Bool) -> Password {
      let password = Password()
      password.secret = secret
      password.algorithm = algorithm
      password.digits = digits
      password.timeBased = timeBased
      return password
  }
}
