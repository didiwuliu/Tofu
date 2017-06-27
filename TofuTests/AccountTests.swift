import XCTest
@testable import Tofu

class AccountTests: XCTestCase {
  func testInitWithURL() {
    var account = Account(url: URL(
      string: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")!)
    XCTAssertEqual(account?.name, "alice@example.com")
    XCTAssertEqual(account?.issuer, "Example")
    XCTAssertEqual(account?.password.timeBased, true)
    XCTAssertEqual(account?.password.secret, Data(base32EncodedString: "JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.password.algorithm, .sha1)
    XCTAssertEqual(account?.password.digits, 6)
    XCTAssertEqual(account?.password.period, 30)

    account = Account(url: URL(
      string: "otpauth://hotp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=1")!)
    XCTAssertEqual(account?.name, "alice@example.com")
    XCTAssertEqual(account?.issuer, "Example")
    XCTAssertEqual(account?.password.timeBased, false)
    XCTAssertEqual(account?.password.secret, Data(base32EncodedString: "JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.password.algorithm, .sha1)
    XCTAssertEqual(account?.password.digits, 6)
    XCTAssertEqual(account?.password.counter, 1)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.name, "alice@example.com")

    account = Account(url: URL(
      string: "otpauth://totp/Example%3Aalice@example.com?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.name, "alice@example.com")

    account = Account(url: URL(
      string: "otpauth://totp/Example:%20%20alice@example.com?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.name, "alice@example.com")

    account = Account(url: URL(
      string: "otpauth://totp/Example%3A%20%20alice@example.com?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.name, "alice@example.com")

    account = Account(url: URL(
      string: "otpauth://totp/example.com/alice?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.name, "example.com/alice")

    account = Account(url: URL(
      string: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.issuer, "Example")

    account = Account(url: URL(string: "otpauth://totp/alice@example.com")!)
    XCTAssertNil(account)

    account = Account(url: URL(string: "otpauth://totp/alice@example.com?secret=AAA")!)
    XCTAssertNil(account)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1")!)
    XCTAssertEqual(account?.password.algorithm, .sha1)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256")!)
    XCTAssertEqual(account?.password.algorithm, .sha256)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512")!)
    XCTAssertEqual(account?.password.algorithm, .sha512)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&digits=6")!)
    XCTAssertEqual(account?.password.digits, 6)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&digits=8")!)
    XCTAssertEqual(account?.password.digits, 8)

    account = Account(url: URL(
      string: "otpauth://hotp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP")!)
    XCTAssertEqual(account?.password.timeBased, false)
    XCTAssertEqual(account?.password.digits, 6)
    XCTAssertEqual(account?.password.counter, 0)

    account = Account(url: URL(
      string: "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP&period=60")!)
    XCTAssertEqual(account?.password.period, 60)
  }

  func testDescription() {
    let account = Account()

    account.name =  "test@example.com"
    account.issuer = "Example"
    XCTAssertEqual(account.description, "Example (test@example.com)")

    account.name =  "test@example.com"
    account.issuer = nil
    XCTAssertEqual(account.description, "test@example.com")

    account.name =  "test@example.com"
    account.issuer = ""
    XCTAssertEqual(account.description, "test@example.com")

    account.name =  nil
    account.issuer = "Example"
    XCTAssertEqual(account.description, "Example")

    account.name =  ""
    account.issuer = "Example"
    XCTAssertEqual(account.description, "Example")

    account.name =  nil
    account.issuer = nil
    XCTAssertEqual(account.description, "")

    account.name =  ""
    account.issuer = ""
    XCTAssertEqual(account.description, "")
  }
}
