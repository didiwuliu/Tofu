import UIKit

private func placeholderImageWithText(_ text: String) -> UIImage {
  let image = UIImage(named: "Placeholder")!
  UIGraphicsBeginImageContextWithOptions(image.size, false, image.scale)
  image.draw(at: CGPoint.zero)
  defer { UIGraphicsEndImageContext() }
  let paragraphStyle = NSMutableParagraphStyle()
  paragraphStyle.alignment = .center
  let fontSize: CGFloat = 36
  let attributes = [
    NSFontAttributeName: UIFont.systemFont(ofSize: fontSize, weight: UIFontWeightUltraLight),
    NSForegroundColorAttributeName: UIColor.lightGray,
    NSParagraphStyleAttributeName: paragraphStyle,
  ]
  let origin = CGPoint(x: 0, y: (image.size.height - fontSize) / 2 - 0.1 * fontSize)
  text.draw(with: CGRect(origin: origin, size: image.size), options: .usesLineFragmentOrigin,
    attributes: attributes, context: nil)
  return UIGraphicsGetImageFromCurrentImageContext()!
}

private func imageForAccount(_ account: Account) -> UIImage {
  switch account.issuer {
  case .some("Amazon"): return UIImage(named: "Amazon")!
  case .some("AWS"): return UIImage(named: "AWS")!
  case .some("Bitbucket"): return UIImage(named: "Bitbucket")!
  case .some("DigitalOcean"): return UIImage(named: "DigitalOcean")!
  case .some("DNSimple"): return UIImage(named: "DNSimple")!
  case .some("Dropbox"): return UIImage(named: "Dropbox")!
  case .some("Evernote"): return UIImage(named: "Evernote")!
  case .some("Facebook"): return UIImage(named: "Facebook")!
  case .some("FastMail"): return UIImage(named: "FastMail")!
  case .some("GitHub"): return UIImage(named: "GitHub")!
  case .some("Google"): return UIImage(named: "Google")!
  case .some("GreenAddress"): return UIImage(named: "GreenAddress")!
  case .some("Heroku"): return UIImage(named: "Heroku")!
  case .some("Hover"): return UIImage(named: "Hover")!
  case .some("IFTTT"): return UIImage(named: "IFTTT")!
  case .some("Intercom"): return UIImage(named: "Intercom")!
  case .some("LinodeManager"): return UIImage(named: "Linode")!
  case .some("LocalBitcoins"): return UIImage(named: "LocalBitcoins")!
  case .some("Microsoft"): return UIImage(named: "Microsoft")!
  case .some("Slack"): return UIImage(named: "Slack")!
  case .some("Stripe"): return UIImage(named: "Stripe")!
  case .some("Tumblr"): return UIImage(named: "Tumblr")!
  case .some("www.fastmail.com"): return UIImage(named: "FastMail")!
  default:
    let text = String(account.description.characters.first ?? "?").uppercased()
    return placeholderImageWithText(text)
  }
}

private func imageWithColor(_ color: UIColor, size: CGSize) -> UIImage {
  UIGraphicsBeginImageContext(size)
  color.setFill()
  UIRectFill(CGRect(x: 0, y: 0, width: size.width, height: size.height))
  let image = UIGraphicsGetImageFromCurrentImageContext()
  UIGraphicsEndImageContext()
  return image!;
}

private func formattedValue(_ value: String) -> String {
  let length = value.characters.count
  let prefix = String(value.characters.prefix(length / 2))
  let suffix = String(value.characters.suffix(length - length / 2))
  return "\(prefix) \(suffix)"
}

final class AccountCell: UITableViewCell {
  @IBOutlet weak var accountImageView: UIImageView!
  @IBOutlet weak var valueLabel: UILabel!
  @IBOutlet weak var identifierLabel: UILabel!
  var delegate: AccountUpdateDelegate?
  fileprivate let button = UIButton(type: .custom)
  fileprivate let progressView = CircularProgressView()

  var account: Account! {
    didSet {
      accessoryView = account.password.timeBased ? progressView : button
      let now = Date()
      updateWithDate(now)
    }
  }

  override func awakeFromNib() {
    let featureSettings = [[
      UIFontFeatureTypeIdentifierKey: kNumberSpacingType,
      UIFontFeatureSelectorIdentifierKey: kMonospacedNumbersSelector]]
    let attributes = [UIFontDescriptorFeatureSettingsAttribute: featureSettings]
    let fontDescriptor = valueLabel.font.fontDescriptor
      .addingAttributes(attributes)
    valueLabel.font = UIFont(descriptor: fontDescriptor, size: 0)
    button.titleLabel?.font = UIFont.boldSystemFont(ofSize: 13)
    button.setTitle("NEXT", for: UIControlState())
    button.setTitleColor(tintColor, for: UIControlState())
    button.setTitleColor(UIColor.white, for: .highlighted)
    button.setTitleColor(UIColor.white, for: .selected)
    button.layer.borderColor = button.tintColor.cgColor
    button.layer.borderWidth = 1
    button.layer.cornerRadius = 4
    button.contentEdgeInsets = UIEdgeInsets(top: 5, left: 10, bottom: 5, right: 10)
    button.sizeToFit()
    let image = imageWithColor(tintColor, size: button.bounds.size)
    button.setBackgroundImage(image, for: .highlighted)
    button.setBackgroundImage(image, for: .selected)
    button.clipsToBounds = true
    button.addTarget(self, action: #selector(didPressButton(_:)), for: .touchUpInside)
  }

  func didPressButton(_ sender: UIButton) {
    account.password.counter += 1
    delegate?.updateAccount(account)
  }

  func updateWithDate(_ date: Date) {
    accountImageView.image = imageForAccount(account)
    valueLabel.text = formattedValue(account.password.valueForDate(date))
    identifierLabel.text = account.description
    progressView.progress = account.password.progressForDate(date)
    progressView.tintColor = account.password.timeIntervalRemainingForDate(date) < 5 ?
      .red : tintColor
  }
}
