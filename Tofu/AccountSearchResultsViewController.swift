import UIKit

private let accountCellIdentifier = "AccountCell"

final class AccountSearchResultsViewController: UITableViewController, AccountUpdateDelegate {
  @IBOutlet var emptyView: UIView!
  var accounts: [Account]! {
    didSet {
      tableView.reloadData()
      tableView.backgroundView = accounts.count == 0 ? emptyView : nil
      tableView.separatorStyle = accounts.count == 0 ? .none : .singleLine
    }
  }

  override func viewDidLoad() {
    super.viewDidLoad()
    let updater = AccountsTableViewUpdater(tableView: tableView)
    updater.startUpdating()
  }

  // MARK: UITableViewDataSource

  override func numberOfSections(in tableView: UITableView) -> Int {
    return 1
  }

  override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
    return accounts.count
  }

  override func tableView(_ tableView: UITableView,
    cellForRowAt indexPath: IndexPath) -> UITableViewCell {
      let cell = tableView.dequeueReusableCell(withIdentifier: accountCellIdentifier,
        for: indexPath) as! AccountCell
      cell.account = accounts[indexPath.row]
      cell.delegate = self
      return cell
  }

  // MARK: UITableViewDelegate

  override func tableView(_ tableView: UITableView,
    shouldShowMenuForRowAt indexPath: IndexPath) -> Bool {
      return true
  }

  override func tableView(_ tableView: UITableView, canPerformAction action: Selector,
    forRowAt indexPath: IndexPath, withSender sender: Any?) -> Bool {
      return action == #selector(copy(_:))
  }

  override func tableView(_ tableView: UITableView, performAction action: Selector,
    forRowAt indexPath: IndexPath, withSender sender: Any?) {
      if action == #selector(copy(_:)) {
        let cell = tableView.cellForRow(at: indexPath) as! AccountCell
        UIPasteboard.general.string = cell.valueLabel.text?
          .replacingOccurrences(of: " ", with: "")
      }
  }

  // MARK: AccountUpdateDelegate

  func updateAccount(_ account: Account) {
    (presentingViewController as! AccountUpdateDelegate).updateAccount(account)
    let row = accounts.index { $0 === account }!
    let indexPath = IndexPath(row: row, section: 0)
    guard let cell = tableView.cellForRow(at: indexPath) as? AccountCell else { return }
    cell.updateWithDate(Date())
  }
}
