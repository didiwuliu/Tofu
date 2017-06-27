import UIKit
// FIXME: comparison operators with optionals were removed from the Swift Standard Libary.
// Consider refactoring the code to use the non-optional operators.
fileprivate func < <T : Comparable>(lhs: T?, rhs: T?) -> Bool {
  switch (lhs, rhs) {
  case let (l?, r?):
    return l < r
  case (nil, _?):
    return true
  default:
    return false
  }
}


private let persistentRefsKey = "persistentRefs"
private let accountSearchResultsViewControllerIdentifier = "AccountSearchResultsViewController"
private let accountCellIdentifier = "AccountCell"
private let scanSegueIdentifier = "ScanSegue"
private let manualSegueIdentifier = "ManualSegue"
private let editAccountSegueIdentifier = "EditAccountSegue"

final class AccountsViewController: UITableViewController, UISearchResultsUpdating,
AccountCreationDelegate, AccountUpdateDelegate {
  @IBOutlet weak var emptyView: UIView!
  fileprivate let keychain = Keychain()
  fileprivate let userDefaults = UserDefaults.standard
  fileprivate var accounts: [Account]!
  fileprivate var searchController: UISearchController!
  fileprivate var alertController: UIAlertController!

  @IBAction func didPressAdd(_ sender: UIBarButtonItem) {
    present(alertController, animated: true, completion: nil)
  }

  override func viewDidLoad() {
    super.viewDidLoad()

    accounts = keychain.accounts
    let persistentRefs = userDefaults.array(forKey: persistentRefsKey) as? [Data] ?? []
    accounts.sort { a, b in
      persistentRefs.index(of: a.persistentRef! as Data)! < persistentRefs.index(of: b.persistentRef! as Data)!
    }
    persistAccountOrder()

    let searchResultsController = storyboard?.instantiateViewController(
      withIdentifier: accountSearchResultsViewControllerIdentifier) as! AccountSearchResultsViewController
    searchController = UISearchController(searchResultsController: searchResultsController)
    searchController.searchResultsUpdater = self
    tableView.tableHeaderView = searchController.searchBar

    alertController = UIAlertController(
      title: "Add Account",
      message: "Add an account by scanning a QR code or enter a secret manually.",
      preferredStyle: .actionSheet)

    let scanQRCodeAction = UIAlertAction(title: "Scan QR Code", style: .default) {
      [unowned self] _ in
      self.performSegue(withIdentifier: scanSegueIdentifier, sender: self)
    }

    let enterManuallyAction = UIAlertAction(title: "Enter Manually", style: .default) {
      [unowned self] _ in
      self.performSegue(withIdentifier: manualSegueIdentifier, sender: self)
    }

    let cancelAction = UIAlertAction(title: "Cancel", style: .cancel, handler: nil)

    alertController.addAction(scanQRCodeAction)
    alertController.addAction(enterManuallyAction)
    alertController.addAction(cancelAction)

    let updater = AccountsTableViewUpdater(tableView: tableView)
    updater.startUpdating()

    updateEditing()
  }

  override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
    if let navigationController = segue.destination as? UINavigationController {
      if let accountCreationViewController = navigationController.topViewController
        as? AccountCreationViewController {
          accountCreationViewController.delegate = self
      } else {
        let scanningViewController = navigationController.topViewController
          as! ScanningViewController
        scanningViewController.delegate = self
      }
    } else {
      let accountUpdateViewController = segue.destination
        as! AccountUpdateViewController
      let cell = sender as! AccountCell
      accountUpdateViewController.delegate = self
      accountUpdateViewController.account = cell.account
    }
  }

  fileprivate func persistAccountOrder() {
    let persistentRefs = accounts.map { $0.persistentRef! }
    userDefaults.set(persistentRefs, forKey: persistentRefsKey)
  }

  fileprivate func updateEditing() {
    if accounts.count == 0 {
      tableView.tableHeaderView = nil
      tableView.backgroundView = emptyView
      tableView.separatorStyle = .none
      navigationItem.leftBarButtonItem = nil
      setEditing(false, animated: true)
    } else {
      tableView.tableHeaderView = searchController.searchBar
      tableView.backgroundView = nil
      tableView.separatorStyle = .singleLine
      navigationItem.leftBarButtonItem = editButtonItem
    }
  }

  // MARK: UITableViewDataSource

  override func tableView(_ tableView: UITableView, canMoveRowAt indexPath: IndexPath) ->
    Bool {
      return true
  }

  override func numberOfSections(in tableView: UITableView) -> Int {
    return 1
  }

  override func tableView(_ tableView: UITableView, moveRowAt sourceIndexPath: IndexPath,
    to destinationIndexPath: IndexPath) {
      accounts.insert(accounts.remove(at: sourceIndexPath.row),
        at: destinationIndexPath.row)
      persistAccountOrder()
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

  override func tableView(
    _ tableView: UITableView,
    commit editingStyle: UITableViewCellEditingStyle,
    forRowAt indexPath: IndexPath) {
      if editingStyle == .delete {
        let alertController = UIAlertController(
          title: "Deleting This Account Will Not Turn Off Two-Factor Authentication",
          message: "Please make sure two-factor authentication is turned off in the issuer's sett" +
          "ings before deleting this account to prevent being locked out.",
          preferredStyle: .actionSheet)

        let deleteAccountAction = UIAlertAction(title: "Delete Account", style: .destructive) { _ in
          self.deleteAccountForRowAtIndexPath(indexPath)
        }

        let cancelAction = UIAlertAction(title: "Cancel", style: .cancel, handler: nil)

        alertController.addAction(deleteAccountAction)
        alertController.addAction(cancelAction)

        present(alertController, animated: true, completion: nil)
      }
  }

  fileprivate func deleteAccountForRowAtIndexPath(_ indexPath: IndexPath) {
    let account = self.accounts[indexPath.row]
    guard self.keychain.deleteAccount(account) else {
      presentTryAgainAlertWithTitle(
        "Could Not Delete Account",
        message: "An error occurred when deleting the account from the keychain.") {
          self.deleteAccountForRowAtIndexPath(indexPath)
      }
      return
    }
    accounts.remove(at: indexPath.row)
    persistAccountOrder()
    tableView.deleteRows(at: [indexPath], with: .automatic)
    updateEditing()
  }

  // MARK: UITableViewDelegate

  override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
    tableView.deselectRow(at: indexPath, animated: true)
    if let cell = tableView.cellForRow(at: indexPath) as? AccountCell {
      performSegue(withIdentifier: editAccountSegueIdentifier, sender: cell)
    }
  }

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

  // MARK: UISearchResultsUpdating

  func updateSearchResults(for searchController: UISearchController) {
    let accountSearchResultsViewController = searchController.searchResultsController
      as! AccountSearchResultsViewController
    accountSearchResultsViewController.accounts = accounts.filter {
      guard let string = searchController.searchBar.text else { return false }
      return $0.description.range(of: string, options: .caseInsensitive, range: nil,
        locale: nil) != nil
    }
  }

  // MARK: AccountCreationDelegate

  func createAccount(_ account: Account) {
    guard keychain.insertAccount(account) else {
      presentTryAgainAlertWithTitle(
        "Could Not Create Account",
        message: "An error occurred when inserting the account into the keychain.") {
          self.createAccount(account)
      }
      return
    }
    accounts.append(account)
    persistAccountOrder()
    let lastRow = accounts.count - 1
    let indexPaths = [IndexPath(row: lastRow, section: 0)]
    tableView.insertRows(at: indexPaths, with: .automatic)
    updateEditing()
  }

  // MARK: AccountUpdateDelegate

  func updateAccount(_ account: Account) {
    guard keychain.updateAccount(account) else {
      presentTryAgainAlertWithTitle(
        "Could Not Update Account",
        message: "An error occurred when persisting the account updates to the keychain.") {
          self.updateAccount(account)
      }
      return
    }
    let row = accounts.index { $0 === account }!
    let indexPath = IndexPath(row: row, section: 0)
    guard let cell = tableView.cellForRow(at: indexPath) as? AccountCell else { return }
    cell.updateWithDate(Date())
  }

  fileprivate func presentTryAgainAlertWithTitle(_ title: String, message: String, handler: @escaping () -> Void) {
    let alertController = UIAlertController(title: title, message: message, preferredStyle: .alert)

    let tryAgainAccountAction = UIAlertAction(title: "Try again", style: .default) { _ in
      handler()
    }

    let cancelAction = UIAlertAction(title: "Cancel", style: .cancel, handler: nil)

    alertController.addAction(tryAgainAccountAction)
    alertController.addAction(cancelAction)

    present(alertController, animated: true, completion: nil)
  }
}
