import XCTest
@testable import Tofu

class NSDataTests: XCTestCase {
  func testInitBase32EncodedString() {
    let tests = [
      ("", ""),
      ("MY======", "f"),
      ("MZXQ====", "fo"),
      ("MZXW6===", "foo"),
      ("MZXW6YQ=", "foob"),
      ("MZXW6YTB", "fooba"),
      ("MZXW6YTBOI======", "foobar"),
      ("MY", "f"),
      ("MZXQ", "fo"),
      ("MZXW6", "foo"),
      ("MZXW6YQ", "foob"),
      ("MZXW6YTB", "fooba"),
      ("MZXW6YTBOI", "foobar"),
      ("mzxw6ytboi", "foobar"),
    ]

    for (actual, expected) in tests {
      XCTAssertEqual(Data(base32EncodedString: actual),
        expected.data(using: String.Encoding.ascii))
    }

    XCTAssertNil(Data(base32EncodedString: "1")) // Invalid character
    XCTAssertNil(Data(base32EncodedString: "A")) // Invalid length
    XCTAssertNil(Data(base32EncodedString: "AAA"))
    XCTAssertNil(Data(base32EncodedString: "AAAAAA"))
    XCTAssertNil(Data(base32EncodedString: "MY==")) // Invalid padding
    XCTAssertNil(Data(base32EncodedString: "MY====="))
    XCTAssertNil(Data(base32EncodedString: "MZXW6Y==="))
  }
}
